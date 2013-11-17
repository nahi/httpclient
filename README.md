## About this fork

I just try to make it work properly (as a browser would) for my use cases.

[![Build Status](https://travis-ci.org/glebtv/httpclient.png?branch=master)](https://travis-ci.org/glebtv/httpclient)
[![Gem Version](https://badge.fury.io/rb/glebtv-httpclient.png)](http://badge.fury.io/rb/glebtv-httpclient)
[![Dependency Status](https://gemnasium.com/glebtv/httpclient.png)](https://gemnasium.com/glebtv/httpclient)

If you don't like how something works, please send a PR or use original gem: https://github.com/nahi/httpclient

## Install

    gem install glebtv-httpclient

or  

    gem 'glebtv-httpclient'

## Basic usage

    clnt = HTTPClient.new()
    clnt.get_content('http://google.com')
    clnt.post_content('http://google.com', body: {...})

## A more complete usage example with a wrapper class:

To serve as a starting point (cannot be used as-is, you will need to adjust settings, paths, etc)

```ruby
class Ht
  attr_accessor :user_agent, :clnt, :cookie_jar, :referer

  def initialize()
    @user_agent = 'test_app'
    
    @cookie_jar = ROOT_PATH + '/cookies.txt'
    @referer = nil
    @clnt = HTTPClient.new

    @clnt.set_cookie_store(@cookie_jar)
    # @clnt.socket_local.host = 'ip here'
    @clnt.transparent_gzip_decompression = true
    # @clnt.debug_dev = STDERR
  end

  def flush_cookies
    @clnt.save_cookie_store
  end

  def urify(uri)
    HTTPClient::Util.urify(uri)
  end

  def request(method, uri, params = nil)
    if method.to_s == 'get'
      query = params
      body = nil
    else
      query = nil
      body = URI.encode_www_form(params)
    end

    process(method, uri, query: query, body: body)
  end

  def process(method, uri, options)
    retry_number = 0
    while retry_number < 10
      options = options.merge(header: headers, follow_redirect: false)
      res = @clnt.request(method, uri.to_s, options)
      if res.redirect?
        if res.see_other? || res.found?
          method = :get
          options.delete(:body)
        end
        @referer = uri.to_s
        uri = @clnt.default_redirect_uri_callback(urify(uri), res)
        $logger.info "redirect to #{uri}"
        retry_number += 1
      else
        @referer = uri.to_s
        if res.ok?
          return res
        else
          puts "BAD RESPONSE FOR #{uri}"
          p options
          puts "HEADER:"
          puts res.header.dump
          puts "CONTENT:"
          puts res.content
          raise HTTPClient::BadResponseError.new("unexpected response", res)
        end
      end
    end
    raise 'redirect loop detected'
  end

  def headers
    ret = {
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language' => 'ru,en;q=0.5',
        'User-Agent' => @user_agent,
    }
    ret['Referer'] = @referer unless @referer.nil?
    ret
  end
end
```


## Original gem readme

httpclient - HTTP accessing library.
Copyright (C) 2000-2012  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.

'httpclient' gives something like the functionality of libwww-perl (LWP) in
Ruby.  'httpclient' formerly known as 'http-access2'.

See HTTPClient for documentation.


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

Usage:

Issues a GET request to the given URI and shows the wiredump and the parsed result: 
  
    % httpclient get https://www.google.co.jp/ q=ruby

Invokes irb shell with the binding that has a HTTPClient as 'self':

    % httpclient

You can call HTTPClient instance methods like:

    > get "https://www.google.co.jp/", :q => :ruby

## Author

Name:: Hiroshi Nakamura
E-mail:: nahi@ruby-lang.org
Project web site:: http://github.com/nahi/httpclient


## License

This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
redistribute it and/or modify it under the same terms of Ruby's license;
either the dual license version in 2003, or any later version.

httpclient/session.rb is based on http-access.rb in http-access/0.0.4.  Some
part of it is copyrighted by Maebashi-san who made and published
http-access/0.0.4.  http-access/0.0.4 did not include license notice but when
I asked Maebashi-san he agreed that I can redistribute it under the same terms
of Ruby.  Many thanks to Maebashi-san.
