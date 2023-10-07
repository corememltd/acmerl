%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme_client).

-export([generate_key/0]).
-export([directory_url/1]).
-export([request/1, request/2, request/3, request/4, request/5]).
-export([thumbprint/1]).
-export([file/1, save/2]).

-include_lib("kernel/include/file.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("public_key/include/public_key.hrl").

-type directory_field() :: newNonce | newAccount | newOrder | newAuthz | revokeCert | keyChange.
-type directory_meta_field() :: meta_termsOfService.

-type request_uri() :: directory_field() | uri_string:uri_string().
-type nonce() :: binary().
-type response_http() :: {httpc:status_code(),[httpc:header()],map() | binary()}.
-type response() :: {response_http(),nonce()}.

-define(ALGORITHM, 'ES256').
-define(USERAGENT, "acme/0.1 (+https://gitlab.com/coremem/dns-wingman/-/tree/master/apps/acme) httpc (Erlang inets)").

%%

-spec generate_key() -> public_key:private_key().
generate_key() ->
	Curve = algorithm2params(?ALGORITHM),
	public_key:generate_key(Curve).

-spec directory_url(directory_field() | directory_meta_field()) -> binary()
		 ; (meta) -> map().
directory_url(meta_termsOfService) ->
	maps:get(atom_to_binary(termsOfService), directory_url(meta));
directory_url(Type) ->
	URL = acme:directory(),
	Request = {URL,request_headers()},
	HTTPOptions = request_options_http(),
	Options = request_options(),
	{ok,{{_HTTPVersion,200,_Reason},Headers,Body0}} = httpc:request(get, Request, HTTPOptions, Options),
	Body = body(200, Headers, Body0),
	maps:get(atom_to_binary(Type), Body).

-spec request(request_uri()) -> {ok,response()}.
request(Type) ->
	request(Type, undefined).
-spec request(request_uri(), public_key:private_key() | undefined) -> {ok,response()}.
request(Type, Key) ->
	request(Type, Key, undefined).
-spec request(request_uri(), public_key:private_key() | undefined, string() | undefined) -> {ok,response()}.
request(Type, Key, Account) ->
	request(Type, Key, Account, undefined).
-spec request(request_uri(), public_key:private_key() | undefined, string() | undefined, nonce() | undefined) -> {ok,response()}.
request(Type, Key, Account, Nonce) ->
	request(Type, Key, Account, Nonce, undefined).
-spec request(request_uri(), public_key:private_key() | undefined, string() | undefined, nonce() | undefined, map() | undefined) -> {ok,response()}.
request(Type, Key, Account, Nonce0, Payload) ->
	URL = if
		Type == newAccount, Account =/= undefined ->
			list_to_binary(Account);
		is_atom(Type) ->
			directory_url(Type);
		is_list(Type) ->
			list_to_binary(Type);
		true ->
			Type
	end,
	case do_request(Type, Key, Account, Nonce0, Payload, URL) of
		{ok,{{400,_Headers,#{ <<"type">> := <<"urn:ietf:params:acme:error:badNonce">> }}, Nonce}} when Nonce0 =/= undefined ->
			do_request(Type, Key, Account, Nonce, Payload, URL);
		Response ->
			Response
	end.

% https://tools.ietf.org/html/rfc7638
-spec thumbprint(public_key:private_key()) -> binary().
thumbprint(Key) ->
	crypto:hash(sha256, jsone:encode(lists:keysort(1, maps:to_list(key2jwk(Key))))).

-spec file(string()) -> file:name().
file(Suffix) ->
	{ok,Application} = application:get_application(),
	filename:join([ code:lib_dir(Application, priv), Suffix ]).

%%

request_headers() ->
	From = hd(lists:filtermap(fun
		({mailto,Email}) ->
			{true,Email};
		(_) ->
			false
	end, acme:contacts())),
	[
		{"user-agent",?USERAGENT},
		{"from",From}
	].

request_options() ->
	[{body_format,binary}].

request_options_http() ->
	SSL = [
		{verify,verify_peer},
		% https://bugs.erlang.org/browse/ERL-1260
		{customize_hostname_check,[{match_fun,public_key:pkix_verify_hostname_match_fun(https)}]},
		{cacertfile,"/etc/ssl/certs/ca-certificates.crt"}
	],
	[{connect_timeout,3000},{timeout,10000},{ssl,SSL}].

do_request(Type, Key, Account, Nonce0, Payload, URL) when Type =/= newNonce, Nonce0 == undefined ->
	{ok,{{200,_Headers,#{}},Nonce}} = request(newNonce),
	true = is_binary(Nonce),
	do_request(Type, Key, Account, Nonce, Payload, URL);
do_request(Type, _Key, _Account, _Nonce, _Payload, URL) when Type == newNonce ->
	Request = {URL,request_headers()},
	HTTPOptions = request_options_http(),
	Options = request_options(),
	{ok,{{_HTTPVersion,200,_Reason},Headers,_Body}} = httpc:request(head, Request, HTTPOptions, Options),
	{ok,{{200,Headers,#{}},nonce(Headers)}};
do_request(Type, Key, Account, Nonce, #{ {} := KeyN }, URL) when Type == keyChange ->
	InnerProtected = #{
		alg	=> key2alg(KeyN),
		jwk	=> key2jwk(KeyN),
		url	=> URL
	},
	InnerPayload = #{
		account	=> list_to_binary(Account),
		oldKey	=> key2jwk(Key)
	},
	InnerProtectedB64URL = base64url:encode(jsone:encode(InnerProtected)),
	InnerPayloadB64URL = base64url:encode(jsone:encode(InnerPayload)),
	JWSSigningInput = <<InnerProtectedB64URL/binary, ".", InnerPayloadB64URL/binary>>,
	InnerSignatureB64URL = base64url:encode(jws(JWSSigningInput, KeyN)),
	Payload = #{
		protected	=> InnerProtectedB64URL,
		payload		=> InnerPayloadB64URL,
		signature	=> InnerSignatureB64URL
	},
	do_request(Type, Key, Account, Nonce, Payload, URL);
do_request(Type, Key, Account, Nonce, Payload, URL) when is_binary(Nonce) ->
	Protected0 = #{
		alg	=> key2alg(Key),
		nonce	=> Nonce,
		url	=> URL
	},
	Protected = if
		Type == newAccount, Account == undefined ->
			maps:put(jwk, key2jwk(Key), Protected0);
		true ->
			maps:put(kid, list_to_binary(Account), Protected0)
	end,
	ProtectedB64URL = base64url:encode(jsone:encode(Protected)),
	PayloadB64URL = if is_map(Payload) -> base64url:encode(jsone:encode(Payload)); true -> <<>> end,
	JWSSigningInput = <<ProtectedB64URL/binary, ".", PayloadB64URL/binary>>,
	SignatureB64URL = base64url:encode(jws(JWSSigningInput, Key)),
	PostBody = jsone:encode(#{
		protected	=> ProtectedB64URL,
		payload		=> PayloadB64URL,
		signature	=> SignatureB64URL
	}),
	Request = {URL,request_headers(),"application/jose+json",PostBody},
	HTTPOptions = request_options_http(),
	Options = request_options(),
	{ok,{{_HTTPVersion,Status,_Reason},Headers,Body0}} = httpc:request(post, Request, HTTPOptions, Options),
	Body = body(Status, Headers, Body0),
	{ok,{{Status,Headers,Body},nonce(Headers)}}.

nonce(Headers) ->
	case lists:keyfind("replay-nonce", 1, Headers) of
		{"replay-nonce",Nonce} ->
			list_to_binary(Nonce);
		_Else ->
			undefined
	end.

body(Status, _Headers, _Body) when Status == 204 ->
	#{};
body(Status, Headers, Body) when Status < 500 ->
	ContentType = case lists:keyfind("content-type", 1, Headers) of {"content-type",CT} -> CT; false -> "" end,
	case lists:splitwith(fun(C) -> C =/= $+ andalso C =/= $; end, ContentType) of
		{"application/json",_Rest} ->
			jsone:decode(Body);
		{_Mime,"+json"} ->
			jsone:decode(Body);
		{_Mime,"+json" ++ _} ->
			jsone:decode(Body);
		_Else ->
			Body
	end;
body(_Status, _Headers, Body) ->
	Body.

% https://tools.ietf.org/html/rfc7518#section-3.4
% https://tools.ietf.org/html/rfc5480#section-2.1.1.1
algorithm2params('ES256') ->
	{namedCurve,secp256r1}.

key2alg(#'ECPrivateKey'{ parameters = {namedCurve,?'secp256r1'} }) ->
	'ES256'.

% https://tools.ietf.org/html/rfc7518#section-6.2
% https://tools.ietf.org/html/rfc5480#section-2.2
% http://davidederosa.com/basic-blockchain-programming/elliptic-curve-keys/
key2jwk(#'ECPrivateKey'{ parameters = {namedCurve,?'secp256r1'}, publicKey = <<4, X:32/binary, Y:32/binary>> }) ->	% uncompressed
	#{
		kty	=> <<"EC">>,
		crv	=> <<"P-256">>,
		x	=> base64url:encode(X),
		y	=> base64url:encode(Y)
	}.

% https://tools.ietf.org/html/rfc7518#section-3.4
jws(Input, Key = #'ECPrivateKey'{ parameters = {namedCurve,?'secp256r1'} }) ->
	Signature = public_key:sign(Input, sha256, Key),
	#'ECDSA-Sig-Value'{ r = R, s = S } = public_key:der_decode('ECDSA-Sig-Value', Signature),
	<<R:32/integer-unit:8, S:32/integer-unit:8>>.

-spec save(file:name(), record:record_frozen()) -> ok | noop | {error,term()}.
save(Name, RF) ->
	try save2(Name, RF) of
		X ->
			X
	catch
		X:Y:Z ->
			?LOG_ERROR("unable to save: ~p", [{X,Y,Z}]),
			file:delete(Name ++ ".tmp"),
			{error,failed}
	end.
save2(Name0, RF) ->
	DirName0 = filename:dirname(Name0),
	BaseName = filename:basename(Name0),
	Name = case file:read_link(DirName0) of
		{ok,DirName} ->
			filename:join([filename:absname_join(filename:dirname(DirName0), DirName), BaseName]);
		{error,_} ->
			Name0
	end,
	RFS = io_lib:fwrite("~tp.~n", [RF]),
	ok = filelib:ensure_dir(Name),
	% https://www.slideshare.net/nan1nan1/eat-my-data
	TmpFile = Name ++ ".tmp",
	file:delete(TmpFile),
	% Erlang has no equivalent of mkstemp()
	{ok,IoDevice} = file:open(TmpFile, [exclusive,raw,{encoding,unicode},sync]),
	{ok,FileInfo} = file:read_file_info(TmpFile),
	ok = file:write_file_info(TmpFile, FileInfo#file_info{ mode = 8#00600 }),
	ok = file:write(IoDevice, RFS),
	ok = file:sync(IoDevice),
	ok = file:close(IoDevice),
	ok = file:rename(TmpFile, Name),
	ok.
