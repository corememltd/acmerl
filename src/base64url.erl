%%% Erlang Base64 URL Module
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: Unlicense

-module(base64url).

-export([encode/1]).
-export([decode/1]).

encode(Data) ->
	Base64 = base64:encode(Data),
	Base64Trimmed = hd(binary:split(Base64, <<"=">>)),
	binary:replace(binary:replace(Base64Trimmed, <<"+">>, <<"-">>, [global]), <<"/">>, <<"_">>, [global]).

decode(Base64URL) ->
	Base64Trimmed = binary:replace(binary:replace(Base64URL, <<"_">>, <<"/">>, [global]), <<"-">>, <<"+">>, [global]),
	Base64 = case byte_size(Base64Trimmed) rem 4 of
		0 ->
			Base64Trimmed;
		2 ->
			<<Base64Trimmed/binary, "==">>;
		3 ->
			<<Base64Trimmed/binary, "=">>
	end,
	base64:decode(Base64).
