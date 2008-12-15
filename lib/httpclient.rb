# HTTPClient - HTTP client library.
# Copyright (C) 2000-2008  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.

# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


# Ruby standard library
require 'uri'
require 'stringio'

# Extra library
require 'httpclient/util'
require 'httpclient/ssl_config'
require 'httpclient/connection'
require 'httpclient/session'
require 'httpclient/http'
require 'httpclient/auth'
require 'httpclient/cookie'


# DESCRIPTION
#   HTTPClient -- Client to retrieve web resources via HTTP.
#
# How to create your client.
#   1. Create simple client.
#     clnt = HTTPClient.new
#
#   2. Accessing resources through HTTP proxy.
#     clnt = HTTPClient.new("http://myproxy:8080")
#
#   3. Set User-Agent and From in HTTP request header.(nil means "No proxy")
#     clnt = HTTPClient.new(nil, "MyAgent", "nahi@keynauts.com")
#
# How to retrieve web resources.
#   1. Get content of specified URL.
#     puts clnt.get_content("http://www.ruby-lang.org/en/")
#
#   2. Do HEAD request.
#     res = clnt.head(uri)
#
#   3. Do GET request with query.
#     res = clnt.get(uri)
#
#   4. Do POST request.
#     res = clnt.post(uri)
#     res = clnt.get|post|head(uri, proxy)
#
class HTTPClient

  VERSION = '2.1.3-SNAPSHOT'
  RUBY_VERSION_STRING = "ruby #{RUBY_VERSION} (#{RUBY_RELEASE_DATE}) [#{RUBY_PLATFORM}]"
  /: (\S+) (\S+)/ =~ %q$Id$
  LIB_NAME = "(#{$1}/#{$2}, #{RUBY_VERSION_STRING})"

  class ConfigurationError < StandardError
  end

  class BadResponse < RuntimeError
    attr_reader :res

    def initialize(msg, res = nil)
      super(msg)
      @res = res
    end
  end

  # for backward compatibility
  class Session
    BadResponse = ::HTTPClient::BadResponse
  end

  attr_reader :agent_name
  attr_reader :from
  attr_reader :ssl_config
  attr_accessor :cookie_manager
  attr_reader :test_loopback_response
  attr_reader :request_filter
  attr_reader :proxy_auth
  attr_reader :www_auth

  attr_accessor :follow_redirect_count
  attr_accessor :protocol_retry_count

  include Util

  class << self
    %w(get_content head get post put delete options propfind trace).each do |name|
      eval <<-EOD
        def #{name}(*arg)
          new.#{name}(*arg)
        end
      EOD
    end
  end

  PROPFIND_DEFAULT_EXTHEADER = { 'Depth' => '0' }

  # SYNOPSIS
  #   Client.new(proxy = nil, agent_name = nil, from = nil)
  #
  # ARGS
  #   proxy             A String of HTTP proxy URL. ex. "http://proxy:8080".
  #   agent_name        A String for "User-Agent" HTTP request header.
  #   from              A String for "From" HTTP request header.
  #
  # DESCRIPTION
  #   Create an instance.
  #   SSLConfig cannot be re-initialized.  Create new client.
  #
  def initialize(proxy = nil, agent_name = nil, from = nil)
    @proxy = nil        # assigned later.
    @no_proxy = nil
    @agent_name = agent_name
    @from = from
    @www_auth = WWWAuth.new
    @proxy_auth = ProxyAuth.new
    @request_filter = [@proxy_auth, @www_auth]
    @debug_dev = nil
    @redirect_uri_callback = method(:default_redirect_uri_callback)
    @test_loopback_response = []
    @session_manager = SessionManager.new(self)
    @session_manager.agent_name = @agent_name
    @session_manager.from = @from
    @session_manager.ssl_config = @ssl_config = SSLConfig.new(self)
    @cookie_manager = WebAgent::CookieManager.new
    @follow_redirect_count = 10
    @protocol_retry_count = 5
    load_environment
    self.proxy = proxy if proxy
  end

  def debug_dev
    @debug_dev
  end

  def debug_dev=(dev)
    @debug_dev = dev
    reset_all
    @session_manager.debug_dev = dev
  end

  def protocol_version
    @session_manager.protocol_version
  end

  def protocol_version=(protocol_version)
    reset_all
    @session_manager.protocol_version = protocol_version
  end

  def connect_timeout
    @session_manager.connect_timeout
  end

  def connect_timeout=(connect_timeout)
    reset_all
    @session_manager.connect_timeout = connect_timeout
  end

  def send_timeout
    @session_manager.send_timeout
  end

  def send_timeout=(send_timeout)
    reset_all
    @session_manager.send_timeout = send_timeout
  end

  def receive_timeout
    @session_manager.receive_timeout
  end

  def receive_timeout=(receive_timeout)
    reset_all
    @session_manager.receive_timeout = receive_timeout
  end

  def proxy
    @proxy
  end

  def proxy=(proxy)
    if proxy.nil?
      @proxy = nil
      @proxy_auth.reset_challenge
    else
      @proxy = urify(proxy)
      if @proxy.scheme == nil or @proxy.scheme.downcase != 'http' or
          @proxy.host == nil or @proxy.port == nil
        raise ArgumentError.new("unsupported proxy #{proxy}")
      end
      @proxy_auth.reset_challenge
      if @proxy.user || @proxy.password
        @proxy_auth.set_auth(@proxy.user, @proxy.password)
      end
    end
    reset_all
    @session_manager.proxy = @proxy
    @proxy
  end

  def no_proxy
    @no_proxy
  end

  def no_proxy=(no_proxy)
    @no_proxy = no_proxy
    reset_all
  end

  # if your ruby is older than 2005-09-06, do not set socket_sync = false to
  # avoid an SSL socket blocking bug in openssl/buffering.rb.
  def socket_sync=(socket_sync)
    @session_manager.socket_sync = socket_sync
  end

  def set_auth(uri, user, passwd)
    uri = urify(uri)
    @www_auth.set_auth(uri, user, passwd)
    reset_all
  end

  # for backward compatibility
  def set_basic_auth(uri, user, passwd)
    uri = urify(uri)
    @www_auth.basic_auth.set(uri, user, passwd)
    reset_all
  end

  def set_proxy_auth(user, passwd)
    uri = urify(uri)
    @proxy_auth.set_auth(user, passwd)
    reset_all
  end

  def set_cookie_store(filename)
    @cookie_manager.cookies_file = filename
    @cookie_manager.load_cookies if filename
  end

  def save_cookie_store
    @cookie_manager.save_cookies
  end

  def redirect_uri_callback=(redirect_uri_callback)
    @redirect_uri_callback = redirect_uri_callback
  end

  def test_loopback_http_response
    @session_manager.test_loopback_http_response
  end

  # SYNOPSIS
  #   Client#get_content(uri, query = nil, extheader = {}, &block = nil)
  #
  # ARGS
  #   uri       an_URI or a_string of uri to connect.
  #   query     a_hash or an_array of query part.  e.g. { "a" => "b" }.
  #             Give an array to pass multiple value like
  #             [["a" => "b"], ["a" => "c"]].
  #   extheader a_hash of extra headers like { "SOAPAction" => "urn:foo" }.
  #   &block    Give a block to get chunked message-body of response like
  #             get_content(uri) { |chunked_body| ... }
  #             Size of each chunk may not be the same.
  #
  # DESCRIPTION
  #   Get a_sring of message-body of response.
  #
  def get_content(uri, query = nil, extheader = {}, &block)
    uri = urify(uri)
    req = create_request('GET', uri, query, nil, extheader)
    follow_redirect(uri, block) { |new_uri, filtered_block|
      req.header.init_request('GET', new_uri, query)
      proxy = no_proxy?(new_uri) ? nil : @proxy
      do_request(req, proxy, &filtered_block)
    }.content
  end

  # DESCRIPTION
  #   POSTs a body.  Despite from post method, it follows redirect response
  #   and posts the body to redirected site.  It's a security risk.  If you
  #   don't understand it, do NOT use this method.
  #
  def post_content(uri, body = nil, extheader = {}, &block)
    uri = urify(uri)
    req = create_request('POST', uri, nil, body, extheader)
    follow_redirect(uri, block) { |new_uri, filtered_block|
      req.header.init_request('POST', new_uri, nil)
      proxy = no_proxy?(new_uri) ? nil : @proxy
      do_request(req, proxy, &filtered_block)
    }.content
  end

  def strict_redirect_uri_callback(uri, res)
    newuri = URI.parse(res.header['location'][0])
    unless newuri.is_a?(URI::HTTP)
      raise BadResponse.new("unexpected location: #{newuri}", res)
    end
    puts "redirect to: #{newuri}" if $DEBUG
    newuri
  end

  def default_redirect_uri_callback(uri, res)
    newuri = URI.parse(res.header['location'][0])
    unless newuri.is_a?(URI::HTTP)
      newuri = uri + newuri
      STDERR.puts("could be a relative URI in location header which is not recommended")
      STDERR.puts("'The field value consists of a single absolute URI' in HTTP spec")
    end
    puts "redirect to: #{newuri}" if $DEBUG
    newuri
  end

  def head(uri, query = nil, extheader = {})
    request('HEAD', uri, query, nil, extheader)
  end

  def get(uri, query = nil, extheader = {}, &block)
    request('GET', uri, query, nil, extheader, &block)
  end

  def post(uri, body = nil, extheader = {}, &block)
    request('POST', uri, nil, body, extheader, &block)
  end

  def put(uri, body = nil, extheader = {}, &block)
    request('PUT', uri, nil, body, extheader, &block)
  end

  def delete(uri, extheader = {}, &block)
    request('DELETE', uri, nil, nil, extheader, &block)
  end

  def options(uri, extheader = {}, &block)
    request('OPTIONS', uri, nil, nil, extheader, &block)
  end

  def propfind(uri, extheader = PROPFIND_DEFAULT_EXTHEADER, &block)
    request('PROPFIND', uri, nil, nil, extheader, &block)
  end
  
  def proppatch(uri, body = nil, extheader = {}, &block)
    request('PROPPATCH', uri, nil, body, extheader, &block)
  end
  
  def trace(uri, query = nil, body = nil, extheader = {}, &block)
    request('TRACE', uri, query, body, extheader, &block)
  end

  def request(method, uri, query = nil, body = nil, extheader = {}, &block)
    uri = urify(uri)
    proxy = no_proxy?(uri) ? nil : @proxy
    req = create_request(method, uri, query, body, extheader)
    if block
      filtered_block = proc { |res, str|
        block.call(str)
      }
    end
    do_request(req, proxy, &filtered_block)
  end

  # Async interface.

  def head_async(uri, query = nil, extheader = {})
    request_async('HEAD', uri, query, nil, extheader)
  end

  def get_async(uri, query = nil, extheader = {})
    request_async('GET', uri, query, nil, extheader)
  end

  def post_async(uri, body = nil, extheader = {})
    request_async('POST', uri, nil, body, extheader)
  end

  def put_async(uri, body = nil, extheader = {})
    request_async('PUT', uri, nil, body, extheader)
  end

  def delete_async(uri, extheader = {})
    request_async('DELETE', uri, nil, nil, extheader)
  end

  def options_async(uri, extheader = {})
    request_async('OPTIONS', uri, nil, nil, extheader)
  end

  def propfind_async(uri, extheader = PROPFIND_DEFAULT_EXTHEADER)
    request_async('PROPFIND', uri, nil, nil, extheader)
  end
  
  def proppatch_async(uri, body = nil, extheader = {})
    request_async('PROPPATCH', uri, nil, body, extheader)
  end
  
  def trace_async(uri, query = nil, body = nil, extheader = {})
    request_async('TRACE', uri, query, body, extheader)
  end

  def request_async(method, uri, query = nil, body = nil, extheader = {})
    uri = urify(uri)
    proxy = no_proxy?(uri) ? nil : @proxy
    req = create_request(method, uri, query, body, extheader)
    do_request_async(req, proxy)
  end

  ##
  # Multiple call interface.

  # ???

  ##
  # Management interface.

  def reset(uri)
    uri = urify(uri)
    @session_manager.reset(uri)
  end

  def reset_all
    @session_manager.reset_all
  end

private

  class RetryableResponse < StandardError # :nodoc:
  end

  class KeepAliveDisconnected < StandardError # :nodoc:
  end

  def do_request(req, proxy, &block)
    conn = Connection.new
    res = nil
    retry_count = @protocol_retry_count
    while retry_count > 0
      begin
        protect_keep_alive_disconnected do
          do_get_block(req, proxy, conn, &block)
        end
        res = conn.pop
        break
      rescue RetryableResponse
        res = conn.pop
        retry_count -= 1
      end
    end
    res
  end

  def do_request_async(req, proxy)
    conn = Connection.new
    t = Thread.new(conn) { |tconn|
      retry_count = @protocol_retry_count
      while retry_count > 0
        begin
          protect_keep_alive_disconnected do
            do_get_stream(req, proxy, tconn)
          end
          break
        rescue RetryableResponse
          retry_count -= 1
        end
      end
    }
    conn.async_thread = t
    conn
  end

  def load_environment
    # http_proxy
    if getenv('REQUEST_METHOD')
      # HTTP_PROXY conflicts with the environment variable usage in CGI where
      # HTTP_* is used for HTTP header information.  Unlike open-uri, we
      # simpley ignore http_proxy in CGI env and use cgi_http_proxy instead.
      self.proxy = getenv('cgi_http_proxy')
    else
      self.proxy = getenv('http_proxy')
    end
    # no_proxy
    self.no_proxy = getenv('no_proxy')
  end

  def getenv(name)
    ENV[name.downcase] || ENV[name.upcase]
  end

  def follow_redirect(uri, block = nil)
    uri = urify(uri)
    retry_number = 0
    if block
      filtered_block = proc { |res, str|
        block.call(str) if HTTP::Status.successful?(res.status)
      }
    end
    while retry_number < @follow_redirect_count
      res = yield(uri, filtered_block)
      if HTTP::Status.successful?(res.status)
        return res
      elsif HTTP::Status.redirect?(res.status)
        uri = urify(@redirect_uri_callback.call(uri, res))
        retry_number += 1
      else
        raise BadResponse.new("unexpected response: #{res.header.inspect}", res)
      end
    end
    raise BadResponse.new("retry count exceeded", res)
  end

  def protect_keep_alive_disconnected
    begin
      yield
    rescue KeepAliveDisconnected
      yield
    end
  end

  def create_request(method, uri, query, body, extheader)
    if extheader.is_a?(Hash)
      extheader = extheader.to_a
    end
    boundary = nil
    content_type = extheader.find { |key, value|
      key.downcase == 'content-type'
    }
    if content_type && content_type[1] =~ /boundary=(.+)\z/
      boundary = $1
    end
    req = HTTP::Message.new_request(method, uri, query, body, boundary)
    extheader.each do |key, value|
      req.header.set(key, value)
    end
    if @cookie_manager && cookies = @cookie_manager.find(uri)
      req.header.set('Cookie', cookies)
    end
    if content_type.nil? and !body.nil?
      req.header.set('content-type', 'application/x-www-form-urlencoded')
    end
    req
  end

  NO_PROXY_HOSTS = ['localhost']

  def no_proxy?(uri)
    if !@proxy or NO_PROXY_HOSTS.include?(uri.host)
      return true
    end
    unless @no_proxy
      return false
    end
    @no_proxy.scan(/([^:,]+)(?::(\d+))?/) do |host, port|
      if /(\A|\.)#{Regexp.quote(host)}\z/i =~ uri.host &&
          (!port || uri.port == port.to_i)
        return true
      end
    end
    false
  end

  # !! CAUTION !!
  #   Method 'do_get*' runs under MT conditon. Be careful to change.
  def do_get_block(req, proxy, conn, &block)
    @request_filter.each do |filter|
      filter.filter_request(req)
    end
    if str = @test_loopback_response.shift
      dump_dummy_request_response(req.body.dump, str) if @debug_dev
      conn.push(HTTP::Message.new_response(str))
      return
    end
    content = block ? nil : ''
    res = HTTP::Message.new_response(content)
    @debug_dev << "= Request\n\n" if @debug_dev
    sess = @session_manager.query(req, proxy)
    res.peer_cert = sess.ssl_peer_cert
    @debug_dev << "\n\n= Response\n\n" if @debug_dev
    do_get_header(req, res, sess)
    conn.push(res)
    sess.get_data() do |part|
      if block
        block.call(res, part)
      else
        content << part
      end
    end
    @session_manager.keep(sess) unless sess.closed?
    commands = @request_filter.collect { |filter|
      filter.filter_response(req, res)
    }
    if commands.find { |command| command == :retry }
      raise RetryableResponse.new
    end
  end

  def do_get_stream(req, proxy, conn)
    @request_filter.each do |filter|
      filter.filter_request(req)
    end
    if str = @test_loopback_response.shift
      dump_dummy_request_response(req.body.dump, str) if @debug_dev
      conn.push(HTTP::Message.new_response(StringIO.new(str)))
      return
    end
    piper, pipew = IO.pipe
    res = HTTP::Message.new_response(piper)
    @debug_dev << "= Request\n\n" if @debug_dev
    sess = @session_manager.query(req, proxy)
    res.peer_cert = sess.ssl_peer_cert
    @debug_dev << "\n\n= Response\n\n" if @debug_dev
    do_get_header(req, res, sess)
    conn.push(res)
    sess.get_data() do |part|
      pipew.syswrite(part)
    end
    pipew.close
    @session_manager.keep(sess) unless sess.closed?
    commands = @request_filter.collect { |filter|
      filter.filter_response(req, res)
    }
    # ignore commands (not retryable in async mode)
  end

  def do_get_header(req, res, sess)
    res.version, res.status, res.reason = sess.get_status
    sess.get_header.each do |key, value|
      res.header.set(key, value)
    end
    if @cookie_manager
      res.header['set-cookie'].each do |cookie|
        @cookie_manager.parse(cookie, req.header.request_uri)
      end
    end
  end

  def dump_dummy_request_response(req, res)
    @debug_dev << "= Dummy Request\n\n"
    @debug_dev << req
    @debug_dev << "\n\n= Dummy Response\n\n"
    @debug_dev << res
  end
end
