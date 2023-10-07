%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme_app).

-behaviour(application).
-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
	true = undefined =/= application:get_env(contacts),
	true = undefined =/= application:get_env(tos),
	true = lists:all(fun env/1, application:get_all_env()),
	acme_sup:start_link().

stop(_State) ->
	ok.

%%

env({Key,_Value0}) when Key == directory ->
	try acme:directory() of
		_Value ->
			true
	catch
		_:_:_ ->
			throw({error,{acme,{env,Key}}})
	end;
env({Key,Value = [_|_]}) when Key == contacts ->
	Valid = lists:all(fun ({mailto,S}) when is_list(S) -> true; (_) -> false end, Value),
	if Valid -> true; true -> throw({error,{acme,{env,Key}}}) end;
env({Key,Value}) when Key == tos, is_list(Value) ->
	true;
env({Key,_Value}) ->
	throw({error,{acme,{env,Key}}}).
