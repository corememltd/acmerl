%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme).

-export([start_link/0]).
-export([directory/0, tos/0, contacts/0]).
-export([tls_options/2]).
-export([challenge/2]).
-export([certificate/2]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-include_lib("kernel/include/logger.hrl").
-include("acme.hrl").

-type directory() :: uri_string:uri_string() | default | letsencrypt | letsencrypt_staging.
-type contact() :: {mailto,string()}.

-type method() :: ?METHOD_TLS_ALPN.

-record(state, {
}).

-record(?MODULE, {
	name,
	options,
	pid,
	monitor
}).
-type ?MODULE() :: #?MODULE{
	name	:: inet_res:dns_name(),
	options	:: list(ssl:server_option()),
	pid	:: pid(),
	monitor	:: reference()
}.

%%

start_link() ->
	gen_server:start_link({local,?MODULE}, ?MODULE, [], []).

-spec directory() -> uri_string:uri_string().
directory() ->
	{ok,Application} = application:get_application(),
	Directory = application:get_env(Application, ?FUNCTION_NAME, default),
	directory(Directory).

-spec tos() -> string().
tos() ->
	{ok,TOS} = application:get_env(?FUNCTION_NAME),
	TOS.

-spec contacts() -> list(contact()).
contacts() ->
	{ok,Contacts} = application:get_env(?FUNCTION_NAME),
	Contacts.

-spec tls_options(inet_res:dns_name(), acme:method()) -> list(ssl:server_option()) | {error,term()} | false.
tls_options(Name, Method) ->
	try ets:lookup_element(?MODULE, Name, #?MODULE.options) of
		Options ->
			Options
	catch
		_:_:_ ->
			acme_client_certificate:tls_options(Name, Method)
	end.

-spec challenge(inet_res:dns_name(), method()) -> map() | {error,term()} | false.
challenge(Name, Method) ->
	acme_client_certificate:challenge(Name, Method).

-spec certificate(inet_res:dns_name(), list(ssl:server_option())) -> ok.
certificate(Name, Options) ->
	gen_server:cast(?MODULE, {?FUNCTION_NAME,Name,Options,self()}).

%%

init(_Args = []) ->
	_Tab = ets:new(?MODULE, [named_table,{keypos,#?MODULE.name},{read_concurrency,true}]),
	{ok,#state{}}.

handle_call(_Request, _From, State) ->
	{stop,badarg,State}.

<<<<<<<<<<<<<< BREAKS RENEWAL?! Maybe best to just send message direct to cert process (do not use ets for options use 'via') >>>>>>>>>>>>>>>>
handle_cast({certificate,Name,Options,Pid}, State) ->
	MonitorRef = monitor(process, Pid),
	Record = #?MODULE{
		name	= Name,
		options	= Options,
		pid	= Pid,
		monitor	= MonitorRef
	},
	true = ets:insert(?MODULE, Record),
	{noreply,State};
handle_cast(_Request, State) ->
	{stop,badarg,State}.

handle_info({'DOWN',MonitorRef,process,Pid,_Reason}, State) ->
	true = ets:match_delete(?MODULE, #?MODULE{ pid = Pid, monitor = MonitorRef, _ = '_' }),
	{noreply,State};
handle_info(Info, State) ->
	?LOG_WARNING("received stray message '~p'", [Info]),
	{noreply,State}.

%%

-spec directory(directory()) -> uri_string:uri_string() | {error,term()}.
directory(default) ->
	directory(letsencrypt_staging);
directory(letsencrypt) ->
	directory("https://acme-v02.api.letsencrypt.org/directory");
directory(letsencrypt_staging) ->
	%% https://letsencrypt.org/docs/staging-environment/
	directory("https://acme-staging-v02.api.letsencrypt.org/directory");
directory(URI0) when is_list(URI0) ->
	case uri_string:normalize(URI0) of URI when is_list(URI) -> URI; Error -> Error end.
