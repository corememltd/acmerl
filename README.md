Erlang [ACME (RFC8555)](https://tools.ietf.org/html/rfc8555) implementation that includes a [ranch transport](https://ninenines.eu/docs/en/ranch/2.0/manual/ranch_transport/) that implements [`tls-alpn-01` (RFC8737)](https://tools.ietf.org/html/rfc8737).

This application requires that all connecting clients uses [TLS SNI](https://en.wikipedia.org/wiki/Server_Name_Indication), none supporting clients are immediately disconnected.

**N.B.** this is not directly usable, please read [why this has been published](https://erlangforums.com/t/https-forward-proxy-in-erlang-mitm-man-in-the-middle/2936/2?u=jimdigriz)

# Usage

## `sys.config`

    {acme,[
      {directory,default},
      {tos,"https://letsencrypt.org/documents/LE-SA-READ_AND_REPLACE_THIS_URL_WITH_ACTUAL_URL.pdf"},
      {contacts,[
        {mailto,"security@example.com"}
      ]}
    ]}

### `directory` [optional]

The ACME directory URL as a string, or alternative one of the the following atoms:

 * **`default`:** alias for `letsencrypt_staging` and used when not supplied
 * **`letsencrypt`:** alias for `"https://acme-v02.api.letsencrypt.org/directory"`
 * **[`letsencrypt_staging`](https://letsencrypt.org/docs/staging-environment/):** alias for `"https://acme-staging-v02.api.letsencrypt.org/directory"`

### `tos` [required]

The value of `termsOfService` from the directory URL as a string.

By matching this value to it, you indicate your agreement to the legal Terms of Service of the ACME directory you use.

If this value mismatches, the account handling component will shutdown preventing certificate issuing and renewal; though any already issued and non-expired certificates will continue to function.

You *must* be prepared for that the `termsOfService` value may change, this application will log a warning to the console but you are responsible for its monitoring.

### `contacts` [required]

List of email addresses (at least one *must* be provided) that *must* be of the form (email address is provided as a string):

    {mailto,"security@example.com"}

The first contact is considered the 'primary' and used as the value for the [`From` HTTP Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/From) when sending requests to the ACME endpoint.

## `ranch_ssl_acme`

`ranch_ssl_acme` is a drop in replacement for [`ranch_ssl`](https://ninenines.eu/docs/en/ranch/2.0/manual/ranch_ssl/) though it does not support the `connect` methods.

Add `ranch_ssl_acme` to your main supervisor with:

    ranch:child_spec(
      my_app_webserver,
      ranch_ssl_acme,
      #{
        socket_opts  => [
          {port,443},
          {sni_hosts,[
            {"example.com",[
              {key,acme},
              {cert,acme},
              {cacerts,acme}
            ]}
          ]}
          % these enable HTTP/2 support
          {next_protocols_advertised,[<<"h2">>,<<"http/1.1">>]},
          {alpn_preferred_protocols,[<<"h2">>,<<"http/1.1">>]}
        ]
      },
      cowboy_tls,
      #{
        env => #{
          dispatch => cowboy_router:compile([
            {'_', [{"/", hello_handler, []}]}
          ])
        }
    )

It may help you to see the large overlap with the configuration above and what you do when configuring a [Cowboy Secure TLS listener](https://ninenines.eu/docs/en/cowboy/2.8/guide/listeners/#_secure_tls_listener).

### `sni_hosts` and `sni_fun` [required]

You must provide either the socket option [`sni_hosts`](https://erlang.org/doc/man/ssl.html#type-sni_hosts) or [`sni_fun`](https://erlang.org/doc/man/ssl.html#type-sni_fun) to return [`[ssl:server_option()]`](https://erlang.org/doc/man/ssl.html#type-server_option).

If you want this application to handle certificate management for a given DNS host you then you must return at least:

    [{key,acme},{cert,acme},{cacerts,acme}]

**N.B.** an error is reported when not all three of these keys are set to the atom `acme`

#### `{acme_method,acme:method()}`

You can also return `acme_method` as one of the options, though the default (and only supported) value is `tls-alpn-01` ([RFC8737](https://tools.ietf.org/html/rfc8737)) and can be omitted.

    [{key,acme},{cert,acme},{cacerts,acme},{acme_method,'tls-alpn-01'}]

### `port` [optional]

The transport expects to be externally presented on port `443/tcp` as [`acme-tls-01` requires this](https://tools.ietf.org/html/rfc8737#section-3); as such it will by default attempt to listen on this port. If you do not have the privileges to do so the transport will delegate the choice to the OS (as if you supplied [`{port,0}`](https://erlang.org/doc/man/gen_tcp.html#listen-2)).

To work around this you can:

 * provide `{port,pos_integer()}` as a `socket_opts` entry to use a static port that you can redirect or point an external load balancer at
 * use [`authbind`](https://mutelight.org/authbind)
 * ...embrace the cavalier side to yourself and run your release as root

When not listening on port `443/tcp` a warning message is printed to the console stating which port the transport is listening on.
