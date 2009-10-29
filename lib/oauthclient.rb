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

  def get_request_token(uri, callback = nil, param = nil)
    oauth_config.token = nil
    oauth_config.secret = nil
    oauth_config.callback = callback
    oauth_config.verifier = nil
    res = request(oauth_config.http_method, uri, param)
    filter_response(res)
    res
  end

  def get_access_token(uri, request_token, request_token_secret, verifier = nil)
    oauth_config.token = request_token
    oauth_config.secret = request_token_secret
    oauth_config.callback = nil
    oauth_config.verifier = verifier
    res = request(oauth_config.http_method, uri)
    filter_response(res)
    res
  end

private

  def unescape(escaped)
    ::HTTPClient::HTTP::Message.unescape(escaped)
  end

  def filter_response(res)
    if res.status == 200
      if res.oauth_params = get_oauth_response(res)
        oauth_config.token = res.oauth_params['oauth_token']
        oauth_config.secret = res.oauth_params['oauth_token_secret']
      end
    end
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
