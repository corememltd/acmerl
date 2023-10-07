%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme_client_event).

-behaviour(gen_event).
-export([init/1, handle_event/2, handle_call/2, handle_info/2]).

-include_lib("kernel/include/logger.hrl").

-record(state, {
	pid	:: pid(),
	monitor	:: reference() | undefined
}).

%%

init(_Args = [Pid]) ->
	MonitorRef = monitor(process, Pid),
	{ok,#state{ pid = Pid, monitor = MonitorRef }}.

handle_event(_Event = {{acme_client_certificate,_Name},Request}, State = #state{ pid = Pid }) ->
	ok = gen_statem:cast(Pid, Request),
	{ok,State};
handle_event(_Event = {acme_client_account,Request}, State = #state{ pid = Pid }) ->
	ok = gen_server:cast(Pid, Request),
	{ok,State}.

handle_call(_Request, _State) ->
	{remove_handler,badarg}.

handle_info(_Info = {'DOWN',MonitorRef,process,Pid,_Reason}, _State = #state{ pid = Pid, monitor = MonitorRef }) ->
	remove_handler;
handle_info(Info, State) ->
	?LOG_WARNING("received stray message '~p'", [Info]),
	{ok,State}.
