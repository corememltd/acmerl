%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme_client_event_manager).

-export([start_link/1]).
-export([add_handler/2]).
-export([notify/2]).

%%

start_link(Name) ->
	gen_event:?FUNCTION_NAME({global,{?MODULE,Name}}).

add_handler(Name, Args) ->
	gen_event:?FUNCTION_NAME({global,{?MODULE,Name}}, {acme_client_event,node()}, Args).

notify(Name, Event) ->
	gen_event:?FUNCTION_NAME({global,{?MODULE,Name}}, {Name,Event}).
