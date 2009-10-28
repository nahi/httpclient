# HTTPClient - HTTP client library.
# Copyright (C) 2000-2009  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.
#
# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


require 'httpclient'
require 'monitor'

module HTTP
  class Message
    attr_accessor :oauth_params
  end
end


# OAuthClient provides OAuth related methods in addition to HTTPClient.
#
# TODO
class OAuthClient < HTTPClient
  attr_accessor :oauth_config

  def initialize(*arg)
    super
    @oauth_config = HTTPClient::OAuth::Config.new
    self.www_auth.oauth.set_config(nil, @oauth_config)
    self.www_auth.oauth.challenge(nil)
  end

  def with_oauth(token, secret, &block)
    @mutex.synchronize do
      @oauth_config.token = token
      @oauth_config.secret = secret
      yield
    end
  end

  def get_request_token(uri)
    oauth_config.token = nil
    oauth_config.secret = nil
    res = get(uri)
    if res.status == 200
      res.oauth_params = get_oauth_response(res)
    end
    res
  end

  def get_access_token(uri, token, secret)
    oauth_config.token = token
    oauth_config.secret = secret
    res = get(uri)
    if res.status == 200
      res.oauth_params = h = get_oauth_response(res)
      oauth_config.token = h['oauth_token']
      oauth_config.secret = h['oauth_token_secret']
    end
    res
  end

private

  def unescape(escaped)
    ::HTTPClient::HTTP::Message.unescape(escaped)
  end

  def get_oauth_response(res)
    enc = res.header['content-encoding']
    body = nil
    if enc and enc[0] and enc[0].downcase == 'gzip'
      body = Zlib::GzipReader.wrap(StringIO.new(res.content)) { |gz| gz.read }
    else
      body = res.content
    end
    body.split('&').inject({}) { |r, e|
      key, value = e.split('=', 2)
      r[unescape(key)] = unescape(value)
      r
    }
  end
end
