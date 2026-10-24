httpclient - HTTP accessing library.  [![Gem Version](https://badge.fury.io/rb/httpclient.svg)](http://badge.fury.io/rb/httpclient)

Copyright (C) 2000-2015  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.

'httpclient' gives something like the functionality of libwww-perl (LWP) in
Ruby.  'httpclient' formerly known as 'http-access2'.

See [HTTPClient](http://www.rubydoc.info/gems/httpclient/frames) for documentation.


## Features

* methods like GET/HEAD/POST/* via HTTP/1.1.
* HTTPS(SSL), Cookies, proxy, authentication(Digest, NTLM, Basic), etc.
* asynchronous HTTP request, streaming HTTP request.
* debug mode CLI.
* by contrast with net/http in standard distribution;
  * Cookies support
  * MT-safe
  * streaming POST (POST with File/IO)
  * Digest auth
  * Negotiate/NTLM auth for WWW-Authenticate (requires net/ntlm module; rubyntlm gem)
  * NTLM auth for Proxy-Authenticate (requires 'win32/sspi' module; rubysspi gem)
  * extensible with filter interface
  * you don't have to care HTTP/1.1 persistent connection
    (httpclient cares instead of you)
* Not supported now
  * Cache
  * Rather advanced HTTP/1.1 usage such as Range, deflate, etc.
    (of course you can set it in header by yourself)

## httpclient command

Usage: 1) `httpclient get https://www.google.co.jp/?q=ruby`  
Usage: 2) `httpclient`

For 1) it issues a GET request to the given URI and shows the wiredump and
the parsed result.  For 2) it invokes irb shell with the binding that has a
HTTPClient as 'self'.  You can call HTTPClient instance methods like;

```ruby
get "https://www.google.co.jp/", :q => :ruby
```

## Author

 * Name:: Hiroshi Nakamura
 * E-mail:: nahi@ruby-lang.org
 * Project web site:: http://github.com/nahi/httpclient


## License

This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
redistribute it and/or modify it under the same terms of Ruby's license;
either the dual license version in 2003, or any later version.

httpclient/session.rb is based on http-access.rb in http-access/0.0.4.  Some
part of it is copyrighted by Maebashi-san who made and published
http-access/0.0.4.  http-access/0.0.4 did not include license notice but when
I asked Maebashi-san he agreed that I can redistribute it under the same terms
of Ruby.  Many thanks to Maebashi-san.


## Install

You can install httpclient via rubygems: `gem install httpclient`


## Usage

See [HTTPClient](http://www.rubydoc.info/gems/httpclient/frames) for documentation.
You can also check sample/howto.rb how to use APIs.

### TLS certificate restrictions

Blocked public keys are identified by their SPKI SHA-256 hashes in
`HTTPClient::SSLConfig::BLOCKED_SPKI_SHA256`. The list covers eight eMudhra
intermediate CA public keys whose corresponding private keys were compromised.

With peer verification enabled and no custom `verify_callback`, HTTPClient
rejects a connection before sending an HTTP request if any certificate supplied
by the server contains a blocked eMudhra public key. This includes cross-signed
certificates and extra certificates that are not used in the verification path,
even when another valid path exists.

Setting `verify_mode` to `OpenSSL::SSL::VERIFY_NONE` or `nil` disables this check.
A custom `verify_callback` replaces the default verification policy, including
the blocked public key check. It receives the underlying verifier's result and
context, and its return value controls certificate verification. The caller is
responsible for the custom callback's validation policy. Hostname verification
is unchanged.

Note: MRI uses HTTPClient's bundled `cacert.pem` by default, while JRuby uses
the JVM's CA certificates and certificate validation. Secure operation on JRuby
depends on keeping the JVM and its CA certificates up to date. HTTPClient's
additional check may not detect blocked intermediates found only in a local
trust store or obtained through JVM issuer retrieval (such as AIA when enabled).

Remove unused certificates containing blocked public keys from the server's
certificate chain configuration. If a certificate containing a blocked public key
is required for validation, replace the affected server certificate and chain
with ones issued under unaffected CA keys.
See [#480](https://github.com/nahi/httpclient/issues/480) for background.

## Bug report or Feature request

Please file a ticket at the project web site.

1. find a similar ticket from https://github.com/nahi/httpclient/issues
2. create a new ticket by clicking 'Create Issue' button.
3. you can use github features such as pull-request if you like.

## Changes

See [ChangeLog](https://github.com/nahi/httpclient/blob/master/CHANGELOG.md)
