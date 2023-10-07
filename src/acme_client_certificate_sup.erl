%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme_client_certificate_sup).

-export([start_link/0]).
-export([start_child/2]).

-behaviour(supervisor).
-export([init/1]).

%%

start_link() ->
	supervisor:start_link({local,?MODULE}, ?MODULE, []).

-spec start_child(inet_res:dns_name(), acme:method()) -> {ok,pid()}.
start_child(Name, Method) ->
	supervisor:?FUNCTION_NAME(?MODULE, [Name,Method]).

%%

init(_Args) ->
	SupFlags = #{
		strategy	=> simple_one_for_one
	},
	ChildSpecs = [#{
		id	=> acme_client_certificate,
		start	=> {acme_client_certificate,start_link,[]}
	}],
	{ok, {SupFlags, ChildSpecs}}.
