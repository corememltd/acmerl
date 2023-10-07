%%% Erlang ACME (RFC8555) Application
%%% Copyright (C) 2020, coreMem Limited <info@coremem.com>
%%% SPDX-License-Identifier: AGPL-3.0-only

-define(PROTOCOL_TLS_ALPN, <<"acme-tls/1">>).		% https://tools.ietf.org/html/rfc8737#section-6.2
-define(METHOD_TLS_ALPN, 'tls-alpn-01').		% https://tools.ietf.org/html/rfc8737#section-6.3
-define(METHOD_TLS_ALPN_BINARY, <<"tls-alpn-01">>).	% https://tools.ietf.org/html/rfc8737#section-6.3
