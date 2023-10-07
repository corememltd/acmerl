%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme_client_certificate).

-export([start_link/2]).
-export([tls_options/2]).
-export([challenge/2]).

-behaviour(gen_statem).
-export([init/1, callback_mode/0, terminate/3]).

% state is order_status()
-export([pending/3]).
-export([ready/3]).
-export([processing/3]).
-export([valid/3]).
-export([invalid/3]).

-include_lib("kernel/include/logger.hrl").
-include_lib("public_key/include/public_key.hrl").

-include("acme.hrl").
-include("record.hrl").

-define(EPOCH_TO_GREGORIAN_SECONDS, calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}})).
-define(CERT_RENEW(NB, NA), (NB + (((NA - NB) div 3) * 2))).

-define(SAVEFILE(X), acme_client:file(X)).

-define(CALL_TLS_OPTIONS,
	?FUNCTION_NAME({call,From}, tls_options, Data = #data{ options = Options }) when is_list(Options) ->
		{keep_state_and_data,[{reply,From,tls_options_build(Data)}]}).

-define(STATE_POSTPONE,
	?CALL_TLS_OPTIONS;
	?FUNCTION_NAME({call,_From}, _EventContent, _Data) ->
		{keep_state_and_data,[{postpone,true}]};
	?FUNCTION_NAME({timeout,_Name}, _EventContent, _Data) ->
		{keep_state_and_data,[{postpone,true}]};
	?FUNCTION_NAME(EventType, _EventContent, _Data) when EventType == cast; EventType == info; EventType == timeout ->
		{keep_state_and_data,[{postpone,true}]}).

-record(data, {
	primary		= false,
	name,
	method		= ?METHOD_TLS_ALPN,

	version		= 0,
	order,
	status,
	authorizations,
	finalize,
	certificate,

	key,
	options
}).
-type data() :: #data{
	primary		:: boolean() | {pid(),reference()},
	name		:: inet_res:dns_name(),
	method		:: acme:method(),

	version		:: non_neg_integer(),
	order		:: uri_string:uri_string() | undefined,
	status		:: order_status() | undefined,
	authorizations	:: list(authorization()) | undefined,
	finalize	:: uri_string:uri_string() | undefined,
	certificate	:: uri_string:uri_string() | undefined,

	key		:: public_key:private_key() | undefined,
	options		:: list(ssl:server_option()) | undefined
}.
-type order_status() :: pending | ready | processing | valid | invalid.

-record(authorization, {
	status,
	url,
	challenges
}).
-type authorization() :: #authorization{
	status		:: authorization_status(),
	url		:: uri_string:uri_string(),
	challenges	:: list(challenge())
}.
-type authorization_status() :: pending | valid | invalid | deactivated | expired | revoked.

-record(challenge, {
	status,
	method,
	url,
	payload
}).
-type challenge() :: #challenge{
	status		:: challenge_status(),
	method		:: acme:method(),
	url		:: uri_string:uri_string(),
	payload		:: map()
}.
-type challenge_status() :: pending | processing | valid | invalid.

%%

-spec start_link(inet_res:dns_name(), acme:method()) -> {ok,pid()}.
start_link(Name, Method) ->
	gen_statem:start_link({via,acme_client_certificate_registry,Name}, ?MODULE, [Name, Method], []).

-spec tls_options(inet_res:dns_name(), acme:method()) -> list(ssl:server_option()) | {error,term()} | false.
tls_options(Name, Method) ->
	acme_client_certificate_sup:start_child(Name, Method),
	try gen_statem:call({via,acme_client_certificate_registry,Name}, ?FUNCTION_NAME) of
		Result ->
			Result
	catch
		_:_:_ ->
			false
	end.

-spec challenge(inet_res:dns_name(), acme:method()) -> map() | {error,term()} | false.
challenge(Name, Method) ->
	try gen_statem:call({global,{?MODULE,Name}}, {?FUNCTION_NAME,Method}) of
		Result ->
			Result
	catch
		_:_:_ ->
			false
	end.

%%

init(_Args = [Name, Method]) ->
	process_flag(trap_exit, true),
	Data = #data{ name = Name, method = Method },
	case file:consult(?SAVEFILE(Name)) of
		{ok,[RF = #record_frozen{ type = ?MODULE }]} ->
			init(data_import(RF, Data));
		{error,enoent} ->
			init(Data);
		Error = {error,_Reason} ->
			{stop,Error}
	end;
init(Data0) when is_record(Data0, data) ->
	case cluster(Data0) of
		Data when is_record(Data, data) ->
			{ok,Data#data.status,Data};
		{error,Reason} ->
			{stop,{shutdown,Reason}}
	end.

callback_mode() ->
	[state_functions,state_enter].

terminate(_Reason, invalid, Data = #data{ version = Version }) ->
	Name = ?SAVEFILE(Data#data.name),
	Backup = Name ++ "." ++ integer_to_list(Version),
	ok = file:rename(Name, Backup),
	ok;
terminate(_Reason, _State, Data) ->
	save(Data), ok.

%%

cluster(Data = #data{ name = Name, primary = false }) ->
	Primary = case global:register_name({?MODULE,Name}, self()) of
		yes ->
			true;
		no ->
			Pid = global:whereis_name({?MODULE,Name}),
			MonitorRef = monitor(process, Pid),	% Pid can be undefined
			{Pid,MonitorRef}
	end,
	cluster(Data#data{ primary = Primary });
cluster(Data0 = #data{ name = Name, primary = true }) ->
	{ok,_Pid} = acme_client_event_manager:start_link({?MODULE,Name}),
	ok = acme_client_event_manager:add_handler({?MODULE,Name}, [self()]),
	Data = order(Data0),
	save_and_notify(Data),
	Data;
cluster(Data = #data{ name = Name, primary = {Pid,_MonitorRef} }) ->
	ok = acme_client_event_manager:add_handler({?MODULE,Name}, [self()]),
	case gen_server:call(Pid, export) of
		DataF = #record_frozen{ type = ?MODULE } ->
			import(DataF, node(Pid), Data);
		Error = {error,_Reason} ->
			Error
	end.

order(Data = #data{ status = valid, options = Options }) when is_list(Options) ->
	{cert,CertDer} = lists:keyfind(cert, 1, Options),
	{NotBefore,NotAfter} = cert_validity(CertDer),
	Now = erlang:system_time(second),
	case erlang:system_time(second) of
		Now when Now > NotAfter ->
			order(Data#data{ status = undefined, options = undefined });
		Now when Now > ?CERT_RENEW(NotBefore, NotAfter) ->
			order(Data#data{ status = undefined });
		_Now ->
			Data
	end;
order(Data0 = #data{ name = Name, order = undefined }) ->
	Payload = #{ identifiers => [ #{ type => dns, value => list_to_binary(Name) } ] },
	{201,Headers,Body} = acme_client_account:request(newOrder, Payload),
	{"location",Order} = lists:keyfind("location", 1, Headers),
	Data = version_update(parse_order(Body, Data0#data{ order = Order })),
	save_and_notify(Data),
	Data;
order(Data0 = #data{ order = Order }) ->
	{200,_Headers,Body} = acme_client_account:request(Order, undefined),
	Data = version_update(parse_order(Body, Data0)),
	save_and_notify(Data),
	Data.

pending(enter, _OldState, Data) ->
	#challenge{ url = URL } = challenge(Data),
	{200,_Headers,_Body} = acme_client_account:request(URL, #{}),
	keep_state_and_data;
pending({call,From}, {challenge,Method}, Data = #data{ method = Method }) ->
	#challenge{ payload = Payload } = challenge(Data),
	{keep_state_and_data,[{reply,From,Payload},{state_timeout,500,poll}]};
pending(state_timeout, poll, Data0) ->
	#challenge{ url = URL } = challenge(Data0),
	{200,_Headers,Body} = acme_client_account:request(URL, undefined),
	case parse_challenge(Body) of
		#challenge{ status = pending } ->
			{keep_state_and_data,[{state_timeout,1000,poll}]};
		_Else ->
			Data = order(Data0),
			{next_state,Data#data.status,Data}
	end;
?STATE_POSTPONE.

ready(enter, _OldState, Data0 = #data{ key = undefined }) ->
	Key = public_key:generate_key({namedCurve,secp256r1}),
	Data = version_update(Data0#data{ key = Key }),
	save_and_notify(Data),
	{repeat_state,Data};
ready(enter, _OldState, _Data) ->
	{keep_state_and_data,[{state_timeout,0,finalize}]};
ready(state_timeout, finalize, Data0 = #data{ name = Name, key = Key, finalize = Finalize }) ->
	PKInfoParametersDer = {asn1_OPENTYPE,public_key:der_encode('EcpkParameters', Key#'ECPrivateKey'.parameters)},
	CSR0 = #'CertificationRequest'{
		certificationRequestInfo = #'CertificationRequestInfo'{
			version				= v1,
			subject				= {rdnSequence,[]},
			subjectPKInfo			= #'CertificationRequestInfo_subjectPKInfo'{
				algorithm			= #'CertificationRequestInfo_subjectPKInfo_algorithm'{
					algorithm			= ?'id-ecPublicKey',
					parameters			= PKInfoParametersDer
				},
				subjectPublicKey	= Key#'ECPrivateKey'.publicKey
			},
			attributes			= [
				#'AttributePKCS-10'{
					type	= ?'pkcs-9-at-extensionRequest',
					values	= [
						{asn1_OPENTYPE,public_key:der_encode('Extensions', [
							#'Extension'{
								extnID          = ?'id-ce-subjectAltName',
								extnValue       = public_key:der_encode('SubjectAltName', [
									{dNSName,Name}
								])
							}
			                        ])}
					]
				}
			]
		},
		signatureAlgorithm = #'CertificationRequest_signatureAlgorithm'{
			algorithm			= ?'ecdsa-with-SHA256',
			parameters			= asn1_NOVALUE
		}
	},
	CertificationRequestInfoDer = public_key:der_encode('CertificationRequestInfo', CSR0#'CertificationRequest'.certificationRequestInfo),
	Signature = public_key:sign(CertificationRequestInfoDer, sha256, Key),
	CSR1 = CSR0#'CertificationRequest'{ signature = Signature },
	CSRB64 = base64url:encode(public_key:der_encode('CertificationRequest', CSR1)),
	{200,_Headers,Body} = acme_client_account:request(Finalize, #{ csr => CSRB64 }),
	Data = version_update(parse_order(Body, Data0)),
	save_and_notify(Data),
	{next_state,Data#data.status,Data};
?STATE_POSTPONE.

processing(enter, _OldState, _Data) ->
	{keep_state_and_data,[{state_timeout,500,poll}]};
processing(state_timeout, poll, Data0) ->
	Data = order(Data0),
	if
		Data#data.status == ?FUNCTION_NAME ->
			{keep_state,Data,[{state_timeout,1000,poll}]};
		true ->
			{next_state,Data#data.status,Data}
	end;
?STATE_POSTPONE.

valid(enter, _OldState, Data0 = #data{ certificate = Certificate, options = undefined }) ->
	{200,Headers,Body} = acme_client_account:request(Certificate, undefined),
	{"content-type","application/pem-certificate-chain"} = lists:keyfind("content-type", 1, Headers),
	[{_,CertDer,_}|CACerts0] = public_key:pem_decode(Body),
	CACerts = lists:map(fun({_,D,_}) -> D end, CACerts0),
	Data = version_update(Data0#data{ options = [{cert,CertDer},{cacerts,CACerts}] }),
	save_and_notify(Data),
	{repeat_state,Data};
valid(enter, _OldState, Data = #data{ name = Name, options = Options }) ->
	ok = acme:certificate(Name, tls_options_build(Data)),
	{cert,CertDer} = lists:keyfind(cert, 1, Options),
	{NotBefore,NotAfter} = cert_validity(CertDer),
	Now = erlang:system_time(second),
	RenewMin = ?CERT_RENEW(NotBefore, NotAfter),
	Renew = if
		RenewMin < Now ->
			(NotAfter - Now) div 7;
		true ->
			RenewMin - Now
	end,
	{keep_state_and_data,[{state_timeout,Renew * 1000,renew}]};
valid({call,From}, export, Data = #data{ primary = true }) ->
	{keep_state_and_data,[{reply,From,data_export(Data)}]};
valid(cast, {data,Pid,DataF}, Data0) ->
	Data = import(DataF, Pid, Data0),
	{keep_state,Data};
valid(cast, {export,Pid}, Data = #data{ primary = true }) ->
	ok = gen_statem:cast(Pid, {data,self(),data_export(Data)}),
	keep_state_and_data;
valid(info, {'DOWN',MonitorRef,process,Pid,_Reason}, Data0 = #data{ primary = {Pid,MonitorRef} }) ->
	case cluster(Data0) of
		Data when is_record(Data, data) ->
			{next_state,Data#data.status,Data};
		{error,Reason} ->
			{stop,{shutdown,Reason}}
	end;
valid(state_timeout, renew, Data0) ->
	Data = order(Data0#data{ status = undefined, options = undefined }),
	{next_state,Data#data.status};
?CALL_TLS_OPTIONS.

invalid(enter, _OldState, Data0 = #data{ options = Options }) when is_list(Options) ->
	Data = Data0#data{ status = valid },
	{keep_state,Data,[{state_timeout,0,retry}]};
invalid(enter, _OldState, _Data) ->
	{stop,{shutdown,invalid}};
invalid(state_timeout, retry, Data) ->
	{next_state,Data#data.status};
?STATE_POSTPONE.

%%

-spec data_export(data()) -> record_frozen().
data_export(Data0 = #data{ version = Version }) when Version > 0 ->
	Data = Data0#data{ primary = false, method = ?METHOD_TLS_ALPN, authorizations = undefined },
	DataF = ?RECORD_FREEZE(data, Data),
	DataF#record_frozen{ type = ?MODULE }.

-spec data_import(record_frozen()) -> data().
data_import(DataF = #record_frozen{ type = ?MODULE }) ->
	Data = ?RECORD_THAW(data, DataF#record_frozen{ type = data }),
	true = Data#data.version > 0,
	Data.
-spec data_import(record_frozen(), data()) -> data().
data_import(DataF = #record_frozen{ type = ?MODULE }, Data0) ->
	Data = data_import(DataF),
	Data#data{ primary = Data0#data.primary, method = Data0#data.method }.

version_update(Data) ->
	Data#data{ version = erlang:system_time(nanosecond) }.

save(Data = #data{ name = Name }) ->
	acme_client:save(?SAVEFILE(Name), data_export(Data)).

notify(Data = #data{ name = Name }) ->
	acme_client_event_manager:notify({?MODULE,Name}, {data,self(),data_export(Data)}).

save_and_notify(Data) ->
	save(Data), notify(Data), ok.

import(DataF = #record_frozen{ type = ?MODULE }, Pid, Data) ->
	import(data_import(DataF, Data), Pid, Data);
import(_DataN = #data{ version = VN }, _Pid, Data0 = #data{ version = V0 }) when VN == V0 ->
	Data0;
import(_DataN = #data{ version = VN }, Pid, Data0 = #data{ version = V0 }) when VN < V0 ->
	gen_server:cast(self(), {export,Pid}),
	Data0;
import(DataN = #data{ version = VN }, Pid, _Data0 = #data{ version = V0, primary = true }) when VN > V0 ->
	?LOG_WARNING("replica '~p' had newer version", [node(Pid)]),
	save_and_notify(DataN),
	DataN;
import(DataN = #data{ version = VN }, _Pid, _Data0 = #data{ version = V0 }) when VN > V0 ->
	save_and_notify(DataN),
	DataN.

tls_options_build(_Data = #data{ key = Key, options = Options }) ->
	{_,KeyDer,_} = public_key:pem_entry_encode('ECPrivateKey', Key),
	[{key,{'ECPrivateKey',KeyDer}}|Options].

-spec cert_validity(public_key:der_encoded()) -> {integer(),integer()}.
cert_validity(CertDer) ->
	#'OTPCertificate'{ tbsCertificate = #'OTPTBSCertificate'{ validity = #'Validity'{ notBefore = NotBefore0, notAfter = NotAfter0 } } } = public_key:pkix_decode_cert(CertDer, otp),
	NotBefore1 = pubkey_cert:time_str_2_gregorian_sec(NotBefore0),
	NotBefore = NotBefore1 - ?EPOCH_TO_GREGORIAN_SECONDS,
	NotAfter1 = pubkey_cert:time_str_2_gregorian_sec(NotAfter0),
	NotAfter = NotAfter1 - ?EPOCH_TO_GREGORIAN_SECONDS,
	{NotBefore,NotAfter}.

-spec authorization(data()) -> authorization().
authorization(_Data = #data{ authorizations = Authorizations }) ->
	[Authorization|_] = lists:filter(fun(#authorization{ status = S }) -> S == pending end, Authorizations),
	Authorization.

-spec challenge(data()) -> challenge().
challenge(Data = #data{ method = Method }) ->
	#authorization{ challenges = Challenges } = authorization(Data),
	[Challenge] = lists:filter(fun(#challenge{ method = M, status = S }) -> M == Method andalso S == pending end, Challenges),
	Challenge.

-spec parse_order_status(binary()) -> order_status().
parse_order_status(<<"pending">>) -> pending;
parse_order_status(<<"ready">>) -> ready;
parse_order_status(<<"processing">>) -> processing;
parse_order_status(<<"valid">>) -> valid;
parse_order_status(<<"invalid">>) -> invalid.

-spec parse_authorization_status(binary()) -> authorization_status().
parse_authorization_status(<<"pending">>) -> pending;
parse_authorization_status(<<"valid">>) -> valid;
parse_authorization_status(<<"invalid">>) -> invalid;
parse_authorization_status(<<"deactivated">>) -> deactivated;
parse_authorization_status(<<"expired">>) -> expired;
parse_authorization_status(<<"revoked">>) -> revoked.

-spec parse_challenge_status(binary()) -> challenge_status().
parse_challenge_status(<<"pending">>) -> pending;
parse_challenge_status(<<"processing">>) -> processing;
parse_challenge_status(<<"valid">>) -> valid;
parse_challenge_status(<<"invalid">>) -> invalid;
parse_challenge_status(<<"deactivated">>) -> deactivated;
parse_challenge_status(<<"expired">>) -> expired;
parse_challenge_status(<<"revoked">>) -> revoked.

-spec parse_method(binary()) -> acme:method() | false.
parse_method(?METHOD_TLS_ALPN_BINARY) -> ?METHOD_TLS_ALPN;
parse_method(_Method) -> false.

parse_order(Body, Data) ->
	Status = parse_order_status(maps:get(<<"status">>, Body)),
	Authorizations = if
		Status == pending ->
			lists:map(fun parse_authorization/1, maps:get(<<"authorizations">>, Body));
		true ->
			undefined
	end,
	Data#data{
		status		= Status,
		authorizations	= Authorizations,
		finalize	= maps:get(<<"finalize">>, Body, undefined),
		certificate	= maps:get(<<"certificate">>, Body, undefined)
	}.

parse_authorization(URL) ->
	{200,_H,B} = acme_client_account:request(URL, undefined),
	#authorization{
		status		= parse_authorization_status(maps:get(<<"status">>, B)),
		url		= URL,
		challenges	= lists:filtermap(fun(C) ->
					case parse_challenge(C) of
						false ->
							false;
						CC ->
							{true,CC}
					end
				  end, maps:get(<<"challenges">>, B))
	}.

-define(CHALLENGE_FILTER, [<<"type">>,<<"url">>,<<"status">>,<<"validated">>,<<"error">>]).
parse_challenge(C) ->
	case parse_method(maps:get(<<"type">>, C)) of
		false ->
			false;
		Method ->
			#challenge{
				method		= Method,
				url		= maps:get(<<"url">>, C),
				status		= parse_challenge_status(maps:get(<<"status">>, C)),
				payload		= maps:without(?CHALLENGE_FILTER, C)
			}
	end.
