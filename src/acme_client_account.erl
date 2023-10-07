%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-module(acme_client_account).

-export([start_link/0]).
-export([request/2]).
-export([thumbprint/0]).
-export([key_rollover/0]).
-export([deactivate/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-include_lib("kernel/include/logger.hrl").

-include("record.hrl").

-define(SAVEFILE, acme_client:file("ACCOUNT")).

-record(state, {
	primary		= false,
	nonce,

	version		= 0,
	directory,
	account,
	tos		= false,
	key
}).
-type state() :: #state{
	primary		:: boolean() | {pid(),reference()},
	nonce		:: acme_client:nonce() | undefined,

	version		:: non_neg_integer(),
	directory	:: uri_string:uri_string() | undefined,
	account		:: uri_string:uri_string() | undefined,
	tos		:: string() | false,
	key		:: public_key:private_key() | undefined
}.

%%

-spec start_link() -> {ok,pid()}.
start_link() ->
	gen_server:start_link({local,?MODULE}, ?MODULE, [], []).

-spec request(acme_client:directory_field(), map() | undefined) -> acme_client:response_http().
request(Type, Payload) ->
	gen_server:call(?MODULE, {?FUNCTION_NAME,Type,Payload}).

-spec thumbprint() -> binary().
thumbprint() ->
	gen_server:call(?MODULE, ?FUNCTION_NAME).

-spec key_rollover() -> ok | {error,term()}.
key_rollover() ->
	gen_server:call({global,?MODULE}, ?FUNCTION_NAME).

-spec deactivate() -> ok | {error,term()}.
deactivate() ->
	gen_server:call({global,?MODULE}, ?FUNCTION_NAME).

%%

init(_Args = []) ->
	process_flag(trap_exit, true),
	State = #state{},
	case file:consult(?SAVEFILE) of
		{ok,[RF = #record_frozen{ type = ?MODULE }]} ->
			init(state_import(RF, State));
		{error,enoent} ->
			init(State);
		Error = {error,_Reason} ->
			{stop,Error}
	end;
init(State = #state{ tos = false }) ->
	Directory = acme:directory(),
	TOS = acme:tos(),
	case string:equal(TOS, acme_client:directory_url(meta_termsOfService)) of
		true ->
			init(State#state{ directory = Directory, tos = TOS });
		false ->
			?LOG_ERROR("terms of service mismatch"),
			ignore
	end;
init(State0 = #state{ directory = Directory }) ->
	case acme:directory() of
		Directory ->
			case cluster(State0) of
				State when is_record(State, state) ->
					{ok,State};
				{error,Reason} ->
					{stop,{shutdown,Reason}}
			end;
		_Else ->
			?LOG_ERROR("directory mismatch"),
			ignore
	end.

handle_call({request,Type,Payload}, _From, State0) ->
	{Response,State} = request(Type, Payload, State0),
	{reply,Response,State};
handle_call(thumbprint, _From, State = #state{ key = Key }) ->
	Thumbprint = acme_client:thumbprint(Key),
	{reply,Thumbprint,State};
handle_call(key_rollover, _From, State0 = #state{ primary = true }) ->
	{Reply,State} = do_key_rollover(State0),
	{reply,Reply,State};
handle_call(deactivate, From, State0 = #state{ primary = true }) ->
	_Result = erpc:multicall(nodes(), gen_server, call, [?MODULE, deactivate], 5000),
	{{200,_Headers,_Body},State} = request(newAccount, #{ status => deactivated }, State0),
	handle_call(deactivate, From, State);
handle_call(deactivate, _From, State) ->
	{reply,{shutdown,deactivate},State};
handle_call(export, _From, State = #state{ primary = true }) ->
	StateExport = state_export(State),
	{reply,StateExport,State};
handle_call(_Request, _From, State) ->
	{stop,badarg,State}.

handle_cast({export,Pid}, State = #state{ primary = true }) ->
	ok = gen_server:cast(Pid, {state,self(),state_export(State)}),
	{noreply,State};
handle_cast({state,Pid,_StateF}, State) when node() == node(Pid) ->
	{noreply,State};
handle_cast({state,Pid,StateF}, State0) ->
	State = import(StateF, Pid, State0),
	{noreply,State};
handle_cast(_Request, State) ->
	{stop,badarg,State}.

handle_info({'DOWN',MonitorRef,process,Pid,_Reason}, State = #state{ primary = {Pid,MonitorRef} }) ->
	case cluster(State#state{ primary = false }) of
		State when is_record(State, state) ->
			{noreply,State};
		{error,Reason} ->
                        {stop,{shutdown,Reason}}
	end;
handle_info(Info, State) ->
	?LOG_WARNING("received stray message '~p'", [Info]),
	{noreply,State}.

terminate({shutdown,deactivate}, _State = #state{ version = Version }) ->
	Name = ?SAVEFILE,
	Backup = Name ++ "." ++ integer_to_list(Version),
	ok = file:rename(Name, Backup),
	ok;
terminate(Reason = {shutdown,{forbidden,_SubReason}}, State = #state{ tos = TOS }) when TOS =/= false ->
	% blank out tos and save so on the restart we shutdown with ignore
	terminate(Reason, version_update(State#state{ tos = false }));
terminate(_Reason, State) ->
	save(State), ok.

%%

cluster(State = #state{ primary = false }) ->
	Primary = case global:register_name(?MODULE, self()) of
		yes ->
			true;
		no ->
			Pid = global:whereis_name(?MODULE),
			MonitorRef = monitor(process, Pid),	% Pid can be undefined
			{Pid,MonitorRef}
	end,
	cluster(State#state{ primary = Primary });
cluster(State = #state{ primary = true, version = 0 }) ->
	NodesVisible = sets:from_list(nodes(visible)),
	NodesConnected = sets:from_list(nodes(connected)),
	case sets:is_subset(NodesVisible, NodesConnected) of
		true ->
			account(State);
		false ->
			{error,nodes_down}
	end;
cluster(State = #state{ primary = true }) ->
	{ok,_Pid} = acme_client_event_manager:start_link(?MODULE),
	ok = acme_client_event_manager:add_handler(?MODULE, [self()]),
	notify(State),
	State;
cluster(State = #state{ primary = {Pid,_MonitorRef} }) ->
	ok = acme_client_event_manager:add_handler(?MODULE, [self()]),
	case gen_server:call(Pid, export) of
		StateF = #record_frozen{ type = ?MODULE } ->
			import(StateF, node(Pid), State);
		Error = {error,_Reason} ->
			Error
	end.

account(State = #state{ primary = true, key = undefined }) ->
	Key = acme_client:generate_key(),
	account(State#state{ key = Key });
account(State = #state{ primary = true, version = Version }) ->
	Now = erlang:system_time(nanosecond),
	if
		is_integer(Version), Now - Version < 3 * 24 * 60 * 60 * 1000000000 ->
			cluster(State);
		true ->
			Payload = #{ termsOfServiceAgreed => true, contact => contacts() },
			account(request(newAccount, Payload, State))
	end;
account({{200,_Headers,_Body},State = #state{ account = Account }}) when Account =/= undefined ->
	save(State),
	cluster(State);
account({{201,Headers,_Body},State0 = #state{ account = undefined, version = 0 }}) ->
	{"location",Account} = lists:keyfind("location", 1, Headers),
	State = version_update(State0#state{ account = Account }),
	save(State),
	cluster(State);
account({{403,Headers,_Body = #{ <<"type">> := Type, <<"detail">> := Detail, <<"instance">> := Instance }}, _State}) ->
	?LOG_ERROR("~s: ~s (~s)", [Type, Detail, Instance]),
	TOSChanged = tos_changed(Headers),
	if
		Type == <<"urn:ietf:params:acme:error:userActionRequired">>, TOSChanged ->
			{error,{forbidden,tos}};
		true ->
			{error,{forbidden,other}}
	end;
account({{Status,_Headers,Body = #{ <<"type">> := Type, <<"detail">> := Detail }},_State}) when Status >= 400, Status < 500 ->
	case maps:get(<<"instance">>, Body, undefined) of
		Instance when is_binary(Instance) ->
			?LOG_ERROR("~s: ~s (~s)", [Type, Detail, Instance]);
		_Else ->
			?LOG_ERROR("~s: ~s", [Type, Detail])
	end,
	{error,client_error};
account({{_Status,_Headers,_Body},_State}) ->
	{error,server_error}.

do_key_rollover(State0 = #state{ version = Version0 }) ->
	Name = ?SAVEFILE,
	Backup = Name ++ "." ++ integer_to_list(Version0),
	ok = file:rename(Name, Backup),
	Key = acme_client:generate_key(),
	State1 = version_update(State0#state{ key = Key }),
	Result = case save(State1) of
		ok ->
			% {} used as the key to guard against accidental JSON encoding and transmission
			try request(keyChange, #{ {} => Key }, State0) of
				{{200,_Headers,_Body},State2} ->
					{ok,State1#state{ nonce = State2#state.nonce }};
				_Else ->
					{error,failed}
			catch
				_:_:_ ->
					{error,failed}
			end;
		Error0 = {error,_Reason} ->
			Error0
	end,
	case Result of
		{ok,State} ->
			% okay not to resave as only the nonce has been updated
			notify(State),
			{ok,State};
		Error ->
			ok = file:rename(Backup, Name),
			{Error,State0}
	end.

request(Type, Payload, State = #state{ key = Key, account = Account, nonce = Nonce0 }) ->
	{ok,{Response = {_Status,_Headers,_Body},Nonce}} = acme_client:request(Type, Key, Account, Nonce0, Payload),
	{Response,State#state{ nonce = Nonce }}.

-spec state_export(state()) -> record_frozen().
state_export(State0 = #state{ version = Version }) when Version > 0 ->
	State = State0#state{ primary = false, nonce = undefined },
	StateF = ?RECORD_FREEZE(state, State),
	StateF#record_frozen{ type = ?MODULE }.

-spec state_import(record_frozen()) -> state().
state_import(StateF = #record_frozen{ type = ?MODULE }) ->
	State = ?RECORD_THAW(state, StateF#record_frozen{ type = state }),
	true = State#state.version > 0,
	State.
-spec state_import(record_frozen(), state()) -> state().
state_import(StateF = #record_frozen{ type = ?MODULE }, State0) ->
	State = state_import(StateF),
	State#state{ primary = State0#state.primary, nonce = State0#state.nonce }.

contacts() ->
	lists:map(fun
		({mailto,Email}) ->
			list_to_binary(["mailto:", Email])
	end, acme:contacts()).

tos_changed(Headers) ->
	lists:any(fun
		({"link",Link}) ->
			lists:any(fun
				(#{ rel := <<"terms-of-service">> }) ->
					true;
				(_) ->
					false
			end, cow_http_hd:parse_link(list_to_binary(Link)));
		(_) ->
			false
	end, Headers).

version_update(State) ->
	State#state{ version = erlang:system_time(nanosecond) }.

save(State) ->
	acme_client:save(?SAVEFILE, state_export(State)).

notify(State) ->
	acme_client_event_manager:notify(?MODULE, {state,self(),state_export(State)}).

save_and_notify(State) ->
	save(State), notify(State), ok.

import(StateF = #record_frozen{ type = ?MODULE }, Pid, State) ->
	import(state_import(StateF, State), Pid, State);
import(_StateN = #state{ version = VN }, _Pid, State0 = #state{ version = V0 }) when VN == V0 ->
	State0;
import(_StateN = #state{ version = VN }, Pid, State0 = #state{ version = V0 }) when VN < V0 ->
	gen_server:cast(self(), {export,Pid}),
	State0;
import(StateN = #state{ version = VN }, Pid, _State0 = #state{ version = V0, primary = true }) when VN > V0 ->
	?LOG_WARNING("replica '~p' had newer version", [node(Pid)]),
	save_and_notify(StateN),
	StateN;
import(StateN = #state{ version = VN }, _Pid, _State0 = #state{ version = V0 }) when VN > V0 ->
	save_and_notify(StateN),
	StateN.
