%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme_client_certificate_registry).

-export([start_link/0]).
-export([register_name/2, unregister_name/1, whereis_name/1, send/2]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-include_lib("kernel/include/logger.hrl").

-record(state, {
}).

-record(?MODULE, {
	name	:: inet_res:dns_name(),
	pid	:: pid(),
	monitor	:: reference()
}).

%%

start_link() ->
	gen_server:start_link({local,?MODULE}, ?MODULE, [], []).

register_name(Name, Pid) ->
	gen_server:call(?MODULE, {?FUNCTION_NAME,{Name,Pid}}).

unregister_name(Name) ->
	gen_server:call(?MODULE, {?FUNCTION_NAME,Name}).

whereis_name(Name) ->
	try ets:lookup_element(?MODULE, Name, #?MODULE.pid) of
		Pid ->
			Pid
	catch
		_:_:_ ->
			undefined
	end.

send(Name, Msg) ->
	case whereis_name(Name) of
		Pid when is_pid(Pid) ->
			Pid ! Name,
			Pid;
		undefined ->
			{badarg,{Name,Msg}}
	end.

%%

init(_Args) ->
	_Tab = ets:new(?MODULE, [named_table,{keypos,#?MODULE.name},{read_concurrency,true}]),
	{ok,#state{}}.

handle_call({register_name,{Name,Pid}}, _From, State) ->
	MonitorRef = monitor(process, Pid),
	Record = #?MODULE{
		name	= Name,
		pid	= Pid,
		monitor	= MonitorRef
	},
	true = ets:insert(?MODULE, Record),
	{reply,yes,State};
handle_call({unregister_name,Name}, _From, State) ->
	case ets:take(?MODULE, Name) of
		[#?MODULE{ monitor = MonitorRef }] ->
			demonitor(MonitorRef);
		[] ->
			ok
	end,
	{reply,ok,State};
handle_call(_Request, _From, State) ->
	{stop,badarg,State}.

handle_cast(_Request, State) ->
	{stop,badarg,State}.

handle_info({'DOWN',MonitorRef,process,Pid,_Reason}, State) ->
	true = ets:match_delete(?MODULE, #?MODULE{ pid = Pid, monitor = MonitorRef, _ = '_' }),
	{noreply,State};
handle_info(Info, State) ->
	?LOG_WARNING("received stray message '~p'", [Info]),
	{noreply,State}.
