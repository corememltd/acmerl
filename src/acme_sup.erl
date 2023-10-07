%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme_sup).

-export([start_link/0]).

-behaviour(supervisor).
-export([init/1]).

start_link() ->
	supervisor:start_link({local,?MODULE}, ?MODULE, []).

init(_Args) ->
	SupFlags = #{
		strategy	=> rest_for_one
	},
	ChildSpecs = [
		#{
			id	=> account,
			start	=> {acme_client_account,start_link,[]}
		},
		#{
			id	=> certificate_registry,
			start	=> {acme_client_certificate_registry,start_link,[]}
		},
		#{
			id	=> certificate,
			start	=> {acme_client_certificate_sup,start_link,[]},
			type	=> supervisor
		},
		#{
			id	=> acme,
			start	=> {acme,start_link,[]}
		}
	],
	{ok, {SupFlags, ChildSpecs}}.
