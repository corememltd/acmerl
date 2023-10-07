%%% Erlang Record Serializer
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: Unlicense

-record(record_frozen, {
	type			:: atom(),
	proplist	= []	:: proplists:proplist()
}).
-type record_frozen() :: #record_frozen{}.

-define(RECORD_FREEZE(T, R), #record_frozen{ type = T, proplist = lists:filtermap(fun
		({_X,Y,Z}) when Y == Z -> false;
		({X,_Y,Z}) -> {true,{X,Z}}
	end, lists:zip3(record_info(fields, T), tl(tuple_to_list(#T{})), tl(tuple_to_list(R)))) }).
-define(RECORD_THAW(T, F), lists:foldl(fun({K,P}, A) ->
	case lists:keyfind(K, 1, F#record_frozen.proplist) of {K,V} -> setelement(P, A, V); false -> A end
end, #T{}, lists:zip(record_info(fields, T), lists:seq(2, record_info(size, T))))).

-define(RECORD_TO_PROPLIST(T, R), lists:zip(record_info(fields, T), tl(tuple_to_list(R)))).
