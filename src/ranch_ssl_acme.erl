%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(ranch_ssl_acme).

-behaviour(ranch_transport).
-export([name/0]).
-export([secure/0]).
-export([messages/0]).
-export([listen/1]).
-export([accept/2]).
-export([handshake/2, handshake/3]).
-export([handshake_continue/2, handshake_continue/3]).
-export([handshake_cancel/1]).
-export([connect/3, connect/4]).
-export([recv/3]).
-export([recv_proxy_header/2]).
-export([send/2]).
-export([sendfile/2, sendfile/4, sendfile/5]).
-export([setopts/2]).
-export([getopts/2]).
-export([getstat/1, getstat/2]).
-export([controlling_process/2]).
-export([peername/1]).
-export([sockname/1]).
-export([shutdown/2]).
-export([close/1]).
-export([cleanup/1]).

-export([negotiated_protocol/1]).

-include_lib("kernel/include/logger.hrl").
-include_lib("public_key/include/public_key.hrl").

% lib/ssl/src/ssl_handshake.hrl:#alpn{}
-record(alpn, {extension_data}).

-include("acme.hrl").

-record(?MODULE, {
	socket		:: ssl:ssl_socket(),
	sni_fun		:: ssl:sni_fun(),
	sni_hosts	:: ssl:sni_hosts(),
	peer		:: list(string()) | undefined
}).

%%

name() ->
	ranch_ssl:?FUNCTION_NAME().

secure() ->
	ranch_ssl:?FUNCTION_NAME().

messages() ->
	ranch_ssl:?FUNCTION_NAME().

listen(TransportOpts) ->
	SocketOpts0 = maps:get(socket_opts, TransportOpts, []),
	SocketOpts1 = case lists:keyfind(handshake, 1, SocketOpts0) of
		{handshake,hello} ->
			SocketOpts0;
		{handshake,_Handshake} ->
			throw({error,{ssl,handshake}});
		false ->
			lists:keystore(handshake, 1, SocketOpts0, {handshake,hello})
	end,
	SNIFunDummy = fun(_ServerName) -> [] end,
	SNIFun = case lists:keyfind(sni_fun, 1, SocketOpts1) of {sni_fun,SF} -> SF; false -> SNIFunDummy end,
	SNIHosts = case lists:keyfind(sni_hosts, 1, SocketOpts1) of {sni_hosts,SH} -> SH; false -> [] end,
	SocketOpts2 = lists:keystore(sni_fun, 1, lists:keydelete(sni_hosts, 1, SocketOpts1), {sni_fun,SNIFunDummy}),
	SocketOpts = case lists:keymember(port, 1, SocketOpts2) of
		false ->
			lists:keystore(port, 1, SocketOpts2, {port,443});
		true ->
			SocketOpts2
	end,
	{ok,LSocket} = case ranch_ssl:?FUNCTION_NAME(TransportOpts#{ socket_opts => SocketOpts }) of
		{error,eacces} ->
			SocketOpts3 = lists:keystore(port, 1, SocketOpts, {port,0}),
			ranch_ssl:?FUNCTION_NAME(TransportOpts#{ socket_opts => SocketOpts3 });
		Else ->
			Else
	end,
	case ranch_ssl:sockname(LSocket) of
		{ok,{_IP,443}} ->
			ok;
		{ok,{_IP,Port}} ->
			?LOG_WARNING("httpd listening on ~b/tcp (rfc8738 only works on 443/tcp)~n", [Port])
	end,
	ALSocket = #?MODULE{
		socket		= LSocket,
		sni_fun		= SNIFun,
		sni_hosts	= SNIHosts
	},
	{ok,ALSocket}.

accept(ALSocket = #?MODULE{ socket = LSocket }, Timeout) ->
	{ok,Socket} = ranch_ssl:?FUNCTION_NAME(LSocket, Timeout),
	{ok,ALSocket#?MODULE{ socket = Socket, peer = ipport(Socket) }}.

handshake(ASocket, Timeout) ->
	?FUNCTION_NAME(ASocket, [], Timeout).

handshake(ASocket = #?MODULE{ socket = Socket }, ServerOptions, Timeout) ->
	handshake2(ASocket, ServerOptions, Timeout, ranch_ssl:?FUNCTION_NAME(Socket, ServerOptions, Timeout)).

handshake_continue(ASocket, Timeout) ->
	?FUNCTION_NAME(ASocket, [], Timeout).

handshake_continue(_ASocket = #?MODULE{ socket = Socket0 }, ServerOptions, Timeout) ->
	case ranch_ssl:?FUNCTION_NAME(Socket0, ServerOptions, Timeout) of
		OK = {ok,_Socket} ->
			OK;
		Else ->
			Else
	end.

handshake_cancel(_ASocket = #?MODULE{ socket = Socket }) ->
	ranch_ssl:?FUNCTION_NAME(Socket).

connect(_Host, _Port, _Opts) ->
	{error,not_supported}.

connect(_Host, _Port, _Opts, _Timeout) ->
	{error,not_supported}.

recv(Socket, Length, Timeout) ->
	ranch_ssl:?FUNCTION_NAME(Socket, Length, Timeout).

recv_proxy_header(_ASocket = #?MODULE{ socket = Socket }, Timeout) ->
	ranch_ssl:?FUNCTION_NAME(Socket, Timeout).

send(Socket, Packet) ->
	ranch_ssl:?FUNCTION_NAME(Socket, Packet).

sendfile(Socket, File) ->
	?FUNCTION_NAME(Socket, File, 0, 0, []).

sendfile(Socket, File, Offset, Bytes) ->
	?FUNCTION_NAME(Socket, File, Offset, Bytes, []).

sendfile(Socket, File, Offset, Bytes, Opts) ->
	ranch_ssl:?FUNCTION_NAME(Socket, File, Offset, Bytes, Opts).

setopts(_ASocket = #?MODULE{ socket = Socket }, SockOpts) ->
	?FUNCTION_NAME(Socket, SockOpts);
setopts(Socket, SockOpts) ->
	ranch_ssl:?FUNCTION_NAME(Socket, SockOpts).

getopts(_ASocket = #?MODULE{ socket = Socket }, SockOpts) ->
	?FUNCTION_NAME(Socket, SockOpts);
getopts(Socket, SockOpts) ->
	ranch_ssl:?FUNCTION_NAME(Socket, SockOpts).

getstat(_ASocket = #?MODULE{ socket = Socket }) ->
	?FUNCTION_NAME(Socket);
getstat(Socket) ->
	ranch_ssl:?FUNCTION_NAME(Socket).

getstat(_ASocket = #?MODULE{ socket = Socket }, SockStats) ->
	?FUNCTION_NAME(Socket, SockStats);
getstat(Socket, SockStats) ->
	ranch_ssl:?FUNCTION_NAME(Socket, SockStats).

controlling_process(_ASocket = #?MODULE{ socket = Socket }, Pid) ->
	?FUNCTION_NAME(Socket, Pid);
controlling_process(Socket, Pid) ->
	ranch_ssl:?FUNCTION_NAME(Socket, Pid).

peername(_ASocket = #?MODULE{ socket = Socket }) ->
	?FUNCTION_NAME(Socket);
peername(Socket) ->
	ranch_ssl:?FUNCTION_NAME(Socket).

sockname(_ASocket = #?MODULE{ socket = Socket }) ->
	?FUNCTION_NAME(Socket);
sockname(Socket) ->
	ranch_ssl:?FUNCTION_NAME(Socket).

shutdown(_ASocket = #?MODULE{ socket = Socket }, How) ->
	?FUNCTION_NAME(Socket, How);
shutdown(Socket, How) ->
	ranch_ssl:?FUNCTION_NAME(Socket, How).

close(_ASocket = #?MODULE{ socket = Socket }) ->
	?FUNCTION_NAME(Socket);
close(Socket) ->
	ranch_ssl:?FUNCTION_NAME(Socket).

cleanup(TransportOpts) ->
	ranch_ssl:?FUNCTION_NAME(TransportOpts).

%%

negotiated_protocol(_ASocket = #?MODULE{ socket = Socket }) ->
	ssl:?FUNCTION_NAME(Socket).

%%

handshake2(ASocket0 = #?MODULE{ peer = Peer }, _ServerOptions, _Timeout, {ok,Socket,_Info = #{ sni := SNI }}) when is_list(SNI), length(SNI) > 64 ->
	ASocket = ASocket0#?MODULE{ socket = Socket },
	?LOG_ERROR("Client (~s) for ~s exceeds 64 characters (letsencrypt/boulder issue #5112)", [Peer, SNI]),
	catch handshake_cancel(ASocket),
	{error,{tls_options,SNI}};
handshake2(ASocket0 = #?MODULE{ peer = Peer }, ServerOptions0, Timeout, {ok,Socket,Info = #{ sni := SNI, alpn := ALPN0 }}) when is_list(SNI) ->
	ASocket = ASocket0#?MODULE{ socket = Socket },
	ServerOptions1 = sni_fun(ASocket, ServerOptions0, SNI),
	{ServerOptions,Method} = case lists:keytake(acme_method, 1, ServerOptions1) of
		{value,{acme_method,M},SO} when M == ?METHOD_TLS_ALPN ->
			{SO,M};
		false ->
			{ServerOptions1,?METHOD_TLS_ALPN}
	end,
	case tls_options_check(ServerOptions) of
		acme ->
			ALPN1 = if is_binary(ALPN0) -> #alpn{ extension_data = ALPN0 }; true -> ALPN0 end,
			ALPN = tls_alpn(ssl_handshake:decode_alpn(ALPN1)),
			handshake3(ASocket, ServerOptions, Timeout, Info, Method, ALPN);
		true ->
			handshake_continue(ASocket, ServerOptions, Timeout);
		false ->
			?LOG_ERROR("Client (~s) for ~s is missing certificate ssl:server_options()", [Peer, SNI]),
			handshake_continue(ASocket, ServerOptions, Timeout);
		error ->
			?LOG_ERROR("Client (~s) for ~s has ssl:server_options() that are broken", [Peer, SNI]),
			catch handshake_cancel(ASocket),
			{error,{acme,{tls_options,SNI}}}
	end;
handshake2(ASocket0 = #?MODULE{ peer = Peer }, _ServerOptions, _Timeout, {ok,Socket,_Info}) ->
	ASocket = ASocket0#?MODULE{ socket = Socket },
	?LOG_NOTICE("Client (~s) not using SNI, closing connection", [Peer]),
	catch handshake_cancel(ASocket),
	{error,{tls_alert,{acme,nosni}}};
handshake2(ASocket = #?MODULE{ peer = Peer }, _ServerOptions, _Timeout, {error,Reason}) ->
	?LOG_NOTICE("Client (~s) connection error ~w", [Peer, Reason]),
	catch handshake_cancel(ASocket),
	{error,{tls_alert,{acme,Reason}}}.

handshake3(ASocket = #?MODULE{ peer = Peer }, ServerOptions0, Timeout, _Info = #{ sni := SNI }, Method, ALPN) when ALPN == undefined; ALPN == false ->
	case acme:tls_options(SNI, Method) of
		ServerOptionsN when is_list(ServerOptionsN) ->
			ServerOptions = merge(ServerOptionsN, ServerOptions0),
			handshake_continue(ASocket, ServerOptions, Timeout);
		false ->
			?LOG_WARNING("Certificate request from ~s for '~ts' is not available", [Peer, SNI]),
			catch handshake_cancel(ASocket),
			{error,{tls_alert,{acme,{noproc,SNI}}}};
		{error,Reason} ->
			?LOG_WARNING("Certificate request from ~s for '~ts' errored with ~w", [Peer, SNI, Reason]),
			catch handshake_cancel(ASocket),
			{error,{tls_alert,{acme,{Reason,SNI}}}}
	end;
handshake3(ASocket0 = #?MODULE{ peer = Peer }, ServerOptions0, Timeout, _Info = #{ sni := SNI }, _Method, ALPN) ->
	case acme:challenge(SNI, ALPN) of	% want 'ALPN' as it is the method being requested ('Method' is from ServerOptions)
		Challenge when is_map(Challenge) ->
			ServerOptions = challenge(SNI, ServerOptions0, Challenge),
			{ok,_ASocket} = handshake_continue(ASocket0, ServerOptions, Timeout),
			% standard requires we close immediately, so we use a suitable error
			% to have ranch do this for us without creating log spam
			{error,closed};
		false ->
			?LOG_WARNING("Challenge request from ~s for '~ts' is not available", [Peer, SNI]),
			catch handshake_cancel(ASocket0),
			{error,{tls_alert,{acme,{noproc,SNI}}}};
		{error,Reason} ->
			?LOG_WARNING("Challenge request from ~s for '~ts' errored with ~w", [Peer, SNI, Reason]),
			catch handshake_cancel(ASocket0),
			{error,{tls_alert,{acme,{Reason,SNI}}}}
	end.

sni_fun(_ASocket = #?MODULE{ sni_fun = SNIFun, sni_hosts = SNIHosts }, ServerOptions, Name) ->
	merge(case lists:keyfind(Name, 1, SNIHosts) of
		{Name,SO} ->
			SO;
		false ->
			SNIFun(Name)
	end, ServerOptions).

tls_options_check(ServerOptions) ->
	Key = tls_options_check_extract(key, ServerOptions),
	Cert = tls_options_check_extract(cert, ServerOptions),
	CACerts = tls_options_check_extract(cacerts, ServerOptions),
	KeyFile = tls_options_check_extract(keyfile, ServerOptions),
	CertFile = tls_options_check_extract(certfile, ServerOptions),
	CACertsFile = tls_options_check_extract(cacertfile, ServerOptions),
	case {Key,Cert,CACerts,KeyFile,CertFile,CACertsFile} of
		{acme,acme,acme,false,false,false} ->
			acme;
		{A,B,C,_AF,_BF,_CF} when A == acme; B == acme; C == acme ->
			error;
		{A,B,C,AF,BF,CF} ->
			(A xor AF) and (B xor BF) and (C xor CF)
	end.

tls_options_check_extract(Key, ServerOptions) ->
	case lists:keyfind(Key, 1, ServerOptions) of {_Key,acme} -> acme; {_Key,_Value} -> true; false -> false end.

-spec tls_alpn(list(ssl:app_level_protocol())) -> acme:method() | false;
              (undefined) -> undefined.
tls_alpn(undefined) ->
	undefined;
tls_alpn([]) ->
	false;
tls_alpn([?PROTOCOL_TLS_ALPN|_Methods]) ->	% https://tools.ietf.org/html/rfc8737#section-6.2
	?METHOD_TLS_ALPN;
tls_alpn([_Method|Methods]) ->
	tls_alpn(Methods).

ipport(ASocket) ->
	{ok,{IP0,Port}} = peername(ASocket),
	IP1 = inet:ntoa(IP0),
	IP = if size(IP0) == 4 -> IP1; true -> [$[,IP1,$]] end,
	[IP,$:,integer_to_list(Port)].

merge(LN, L0) ->
	orddict:merge(fun(_K,VN,_V0) -> VN end, orddict:from_list(LN), orddict:from_list(L0)).

system_time_to_general_time(Time) ->
	{generalTime,lists:filter(fun(C) ->
		(C >= $0 andalso C =< $9) orelse C == $Z
	end, calendar:system_time_to_rfc3339(Time, [{offset,"Z"}]))}.

-define('id-pe-acmeIdentifier', erlang:append_element(?'id-pe', 31)).
challenge(Name, ServerOptions, #{ <<"token">> := Token }) ->
	% https://tools.ietf.org/html/rfc8555#section-8.1
	KeyAuthorization = [Token, $., base64url:encode(acme_client_account:thumbprint())],
	% ASN.1 encoder, poormans approach could replace this with <<4, (size(Hash)):8, Hash/binary>>
	{ok,ACMEIdentifier} = 'ACMEIdentifier':encode('Authorization', crypto:hash(sha256, KeyAuthorization)),
	% otp:lib/public_key/test/erl_make_certs.erl:make_cert/1
	% secp256k1 causes 'tls12_check_peer_sigalg:wrong curve' in openssl
	Key = public_key:generate_key({namedCurve,secp256r1}),
	{_,KeyDer,_} = public_key:pem_entry_encode('ECPrivateKey', Key),
	Now = erlang:system_time(second),
	Subject = {rdnSequence,[
		[
			#'AttributeTypeAndValue'{
				type	= ?'id-at-commonName',
				value	= {utf8String,Name}
			}
		]
	]},
	Cert = #'OTPTBSCertificate'{
		version			= v3,
		serialNumber		= 1,
		issuer			= Subject,
		subject			= Subject,
		subjectPublicKeyInfo	= #'OTPSubjectPublicKeyInfo'{
			algorithm		= #'PublicKeyAlgorithm'{
				algorithm		= ?'id-ecPublicKey',
				parameters		= Key#'ECPrivateKey'.parameters
			},
			subjectPublicKey	= #'ECPoint'{
				point			= Key#'ECPrivateKey'.publicKey
			}
		},
		validity		= #'Validity'{
			notBefore		= system_time_to_general_time(Now - 10),
			notAfter		= system_time_to_general_time(Now + 10)
		},
		extensions		= [
			#'Extension'{
				extnID		= ?'id-ce-subjectAltName',
				extnValue	= [
					{dNSName,Name}
				]
			},
			#'Extension'{
				extnID		= ?'id-pe-acmeIdentifier',
				extnValue	= ACMEIdentifier,
				critical	= true
			}
		],
		signature		= #'SignatureAlgorithm'{
			algorithm		= ?'ecdsa-with-SHA256'
		}
	},
	CertDER = public_key:pkix_sign(Cert, Key),
	lists:keystore(alpn_preferred_protocols, 1,
		lists:keydelete(cacerts, 1,
			lists:keystore(cert, 1,
				lists:keystore(key, 1, ServerOptions, {key,{'ECPrivateKey',KeyDer}}),
			{cert,CertDER})
		),
	{alpn_preferred_protocols,[?PROTOCOL_TLS_ALPN]}).
