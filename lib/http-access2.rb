# HTTPAccess2 - HTTP accessing library.
# Copyright (C) 2000-2005  NAKAMURA, Hiroshi  <nakahiro@sarion.co.jp>.

# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.

# http-access2.rb is based on http-access.rb in http-access/0.0.4.  Some part
# of code in http-access.rb was recycled in http-access2.rb.  Those part is
# copyrighted by Maehashi-san.


# Ruby standard library
require 'timeout'
require 'uri'
require 'socket'
require 'thread'

# Extra library
require 'http-access2/http'
require 'http-access2/cookie'


module HTTPAccess2
  VERSION = '2.0.7'
  RUBY_VERSION_STRING = "ruby #{RUBY_VERSION} (#{RUBY_RELEASE_DATE}) [#{RUBY_PLATFORM}]"
  s = %w$Id$
  RCS_FILE, RCS_REVISION = s[1][/.*(?=,v$)/], s[2]

  SSLEnabled = begin
      require 'openssl'
      true
    rescue LoadError
      false
    end

  DEBUG_SSL = true


module Util
  def urify(uri)
    if uri.is_a?(URI)
      uri
    else
      URI.parse(uri.to_s)
    end
  end
end


# DESCRIPTION
#   HTTPAccess2::Client -- Client to retrieve web resources via HTTP.
#
# How to create your client.
#   1. Create simple client.
#     clnt = HTTPAccess2::Client.new
#
#   2. Accessing resources through HTTP proxy.
#     clnt = HTTPAccess2::Client.new("http://myproxy:8080")
#
#   3. Set User-Agent and From in HTTP request header.(nil means "No proxy")
#     clnt = HTTPAccess2::Client.new(nil, "MyAgent", "nahi@keynauts.com")
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
class Client
  include Util

  attr_reader :agent_name
  attr_reader :from
  attr_reader :ssl_config
  attr_accessor :cookie_manager
  attr_reader :test_loopback_response

  class << self
    %w(get_content head get post put delete options trace).each do |name|
      eval <<-EOD
        def #{name}(*arg)
          new.#{name}(*arg)
        end
      EOD
    end
  end

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
    @proxy_auth = nil
    @no_proxy = nil
    @agent_name = agent_name
    @from = from
    @basic_auth = BasicAuth.new(self)
    @debug_dev = nil
    @ssl_config = SSLConfig.new(self)
    @redirect_uri_callback = method(:default_redirect_uri_callback)
    @test_loopback_response = []
    @session_manager = SessionManager.new
    @session_manager.agent_name = @agent_name
    @session_manager.from = @from
    @session_manager.ssl_config = @ssl_config
    @cookie_manager = WebAgent::CookieManager.new
    self.proxy = proxy
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
      @proxy_auth = nil
    else
      @proxy = urify(proxy)
      if @proxy.scheme == nil or @proxy.scheme.downcase != 'http' or
          @proxy.host == nil or @proxy.port == nil
        raise ArgumentError.new("unsupported proxy `#{proxy}'")
      end
      @proxy_auth = nil
      if @proxy.user || @proxy.password
        @proxy_auth = [@proxy.user, @proxy.password]
      end
    end
    reset_all
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

  def set_basic_auth(uri, user_id, passwd)
    uri = urify(uri)
    @basic_auth.set(uri, user_id, passwd)
  end

  def set_cookie_store(filename)
    if @cookie_manager.cookies_file
      raise RuntimeError.new("overriding cookie file location")
    end
    @cookie_manager.cookies_file = filename
    @cookie_manager.load_cookies if filename
  end

  def save_cookie_store
    @cookie_manager.save_cookies
  end

  def redirect_uri_callback=(redirect_uri_callback)
    @redirect_uri_callback = redirect_uri_callback
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
    retry_connect(uri, query) { |uri, query|
      get(uri, query, extheader, &block)
    }.content
  end

  def post_content(uri, body = nil, extheader = {}, &block)
    retry_connect(uri, nil) { |uri, query|
      post(uri, body, extheader, &block)
    }.content
  end

  def strict_redirect_uri_callback(uri, res)
    newuri = URI.parse(res.header['location'][0])
    puts "Redirect to: #{newuri}" if $DEBUG
    newuri
  end

  def default_redirect_uri_callback(uri, res)
    newuri = URI.parse(res.header['location'][0])
    unless newuri.is_a?(URI::HTTP)
      newuri = uri + newuri
      STDERR.puts(
        "could be a relative URI in location header which is not recommended")
      STDERR.puts(
        "'The field value consists of a single absolute URI' in HTTP spec")
    end
    puts "Redirect to: #{newuri}" if $DEBUG
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

  def trace(uri, query = nil, body = nil, extheader = {}, &block)
    request('TRACE', uri, query, body, extheader, &block)
  end

  def request(method, uri, query = nil, body = nil, extheader = {}, &block)
    conn = Connection.new
    conn_request(conn, method, uri, query, body, extheader, &block)
    conn.pop
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

  def trace_async(uri, query = nil, body = nil, extheader = {})
    request_async('TRACE', uri, query, body, extheader)
  end

  def request_async(method, uri, query = nil, body = nil, extheader = {})
    conn = Connection.new
    t = Thread.new(conn) { |tconn|
      conn_request(tconn, method, uri, query, body, extheader)
    }
    conn.async_thread = t
    conn
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

  def retry_connect(uri, query = nil)
    retry_number = 0
    while retry_number < 10
      res = yield(uri, query)
      if res.status == HTTP::Status::OK
        return res
      elsif HTTP::Status.redirect?(res.status)
        uri = @redirect_uri_callback.call(uri, res)
        query = nil
        retry_number += 1
      else
        raise RuntimeError.new("Unexpected response: #{res.header.inspect}")
      end
    end
    raise RuntimeError.new("Retry count exceeded.")
  end

  def conn_request(conn, method, uri, query, body, extheader, &block)
    uri = urify(uri)
    proxy = no_proxy?(uri) ? nil : @proxy
    begin
      req = create_request(method, uri, query, body, extheader, !proxy.nil?)
      do_get_block(req, proxy, conn, &block)
    rescue Session::KeepAliveDisconnected
      req = create_request(method, uri, query, body, extheader, !proxy.nil?)
      do_get_block(req, proxy, conn, &block)
    end
  end

  def create_request(method, uri, query, body, extheader, proxy)
    if extheader.is_a?(Hash)
      extheader = extheader.to_a
    end
    if @proxy_auth
      proxy_cred = ["#{@proxy_auth[0]}:#{@proxy_auth[1]}"].pack('m').strip
      extheader << ['Proxy-Authorization', "Basic " << proxy_cred]
    end
    cred = @basic_auth.get(uri)
    if cred
      extheader << ['Authorization', "Basic " << cred]
    end
    if cookies = @cookie_manager.find(uri)
      extheader << ['Cookie', cookies]
    end
    boundary = nil
    content_type = extheader.find { |key, value|
      key.downcase == 'content-type'
    }
    if content_type && content_type[1] =~ /boundary=(.+)\z/
      boundary = $1
    end
    req = HTTP::Message.new_request(method, uri, query, body, proxy, boundary)
    extheader.each do |key, value|
      req.header.set(key, value)
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
    if str = @test_loopback_response.shift
      dump_dummy_request_response(req.body.dump, str) if @debug_dev
      conn.push(HTTP::Message.new_response(str))
      return
    end
    content = ''
    res = HTTP::Message.new_response(content)
    @debug_dev << "= Request\n\n" if @debug_dev
    sess = @session_manager.query(req, proxy)
    @debug_dev << "\n\n= Response\n\n" if @debug_dev
    do_get_header(req, res, sess)
    conn.push(res)
    sess.get_data() do |str|
      block.call(str) if block
      content << str
    end
    @session_manager.keep(sess) unless sess.closed?
  end

  def do_get_stream(req, proxy, conn)
    if str = @test_loopback_response.shift
      dump_dummy_request_response(req.body.dump, str) if @debug_dev
      conn.push(HTTP::Message.new_response(str))
      return
    end
    piper, pipew = IO.pipe
    res = HTTP::Message.new_response(piper)
    @debug_dev << "= Request\n\n" if @debug_dev
    sess = @session_manager.query(req, proxy)
    @debug_dev << "\n\n= Response\n\n" if @debug_dev
    do_get_header(req, res, sess)
    conn.push(res)
    sess.get_data() do |str|
      pipew.syswrite(str)
    end
    pipew.close
    @session_manager.keep(sess) unless sess.closed?
  end

  def do_get_header(req, res, sess)
    res.version, res.status, res.reason = sess.get_status
    sess.get_header().each do |line|
      unless /^([^:]+)\s*:\s*(.*)$/ =~ line
        raise RuntimeError.new("Unparsable header: '#{line}'.") if $DEBUG
      end
      res.header.set($1, $2)
    end
    if res.header['set-cookie']
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


# HTTPAccess2::SSLConfig -- SSL configuration of a client.
#
class SSLConfig # :nodoc:
  attr_reader :client_cert
  attr_reader :client_key
  attr_reader :client_ca

  attr_reader :verify_mode
  attr_reader :verify_depth
  attr_reader :verify_callback

  attr_reader :timeout
  attr_reader :options
  attr_reader :ciphers

  attr_reader :cert_store       # don't use if you don't know what it is.

  def initialize(client)
    return unless SSLEnabled
    @client = client
    @cert_store = OpenSSL::X509::Store.new
    @client_cert = @client_key = @client_ca = nil
    @verify_mode = OpenSSL::SSL::VERIFY_PEER |
      OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    @verify_depth = nil
    @verify_callback = nil
    @dest = nil
    @timeout = nil
    @options = defined?(OpenSSL::SSL::OP_ALL) ?
      OpenSSL::SSL::OP_ALL | OpenSSL::SSL::OP_NO_SSLv2 : nil
    @ciphers = "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
  end

  def set_client_cert_file(cert_file, key_file)
    @client_cert = OpenSSL::X509::Certificate.new(File.open(cert_file).read)
    @client_key = OpenSSL::PKey::RSA.new(File.open(key_file).read)
    change_notify
  end

  def set_trust_ca(trust_ca_file_or_hashed_dir)
    if FileTest.directory?(trust_ca_file_or_hashed_dir)
      @cert_store.add_path(trust_ca_file_or_hashed_dir)
    else
      @cert_store.add_file(trust_ca_file_or_hashed_dir)
    end
    change_notify
  end

  def set_crl(crl_file)
    crl = OpenSSL::X509::CRL.new(File.open(crl_file).read)
    @cert_store.add_crl(crl)
    @cert_store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
    change_notify
  end

  def client_cert=(client_cert)
    @client_cert = client_cert
    change_notify
  end

  def client_key=(client_key)
    @client_key = client_key
    change_notify
  end

  def client_ca=(client_ca)
    @client_ca = client_ca
    change_notify
  end

  def verify_mode=(verify_mode)
    @verify_mode = verify_mode
    change_notify
  end

  def verify_depth=(verify_depth)
    @verify_depth = verify_depth
    change_notify
  end

  def verify_callback=(verify_callback)
    @verify_callback = verify_callback
    change_notify
  end

  def timeout=(timeout)
    @timeout = timeout
    change_notify
  end

  def options=(options)
    @options = options
    change_notify
  end

  def ciphers=(ciphers)
    @ciphers = ciphers
    change_notify
  end

  # don't use if you don't know what it is.
  def cert_store=(cert_store)
    @cert_store = cert_store
    change_notify
  end

  # interfaces for SSLSocketWrap.

  def set_context(ctx)
    # Verification: Use Store#verify_callback instead of SSLContext#verify*?
    ctx.cert_store = @cert_store
    ctx.verify_mode = @verify_mode
    ctx.verify_depth = @verify_depth if @verify_depth
    ctx.verify_callback = @verify_callback || method(:default_verify_callback)
    # SSL config
    ctx.cert = @client_cert
    ctx.key = @client_key
    ctx.client_ca = @client_ca
    ctx.timeout = @timeout
    ctx.options = @options
    ctx.ciphers = @ciphers
  end

  # this definition must match with the one in ext/openssl/lib/openssl/ssl.rb
  def post_connection_check(peer_cert, hostname)
    check_common_name = true
    cert = peer_cert
    cert.extensions.each{|ext|
      next if ext.oid != "subjectAltName"
      ext.value.split(/,\s+/).each{|general_name|
        if /\ADNS:(.*)/ =~ general_name
          check_common_name = false
          reg = Regexp.escape($1).gsub(/\\\*/, "[^.]+")
          return true if /\A#{reg}\z/i =~ hostname
        elsif /\AIP Address:(.*)/ =~ general_name
          check_common_name = false
          return true if $1 == hostname
        end
      }
    }
    if check_common_name
      cert.subject.to_a.each{|oid, value|
        if oid == "CN"
          reg = Regexp.escape(value).gsub(/\\\*/, "[^.]+")
          return true if /\A#{reg}\z/i =~ hostname
        end
      }
    end
    raise OpenSSL::SSL::SSLError, "hostname not match"
  end

  # Default callback for verification: only dumps error.
  def default_verify_callback(is_ok, ctx)
    if $DEBUG
      puts "#{ is_ok ? 'ok' : 'ng' }: #{ctx.current_cert.subject}"
    end
    if !is_ok
      depth = ctx.error_depth
      code = ctx.error
      msg = ctx.error_string
      STDERR.puts "at depth #{depth} - #{code}: #{msg}"
    end
    is_ok
  end

  # Sample callback method:  CAUTION: does not check CRL/ARL.
  def sample_verify_callback(is_ok, ctx)
    unless is_ok
      depth = ctx.error_depth
      code = ctx.error
      msg = ctx.error_string
      STDERR.puts "at depth #{depth} - #{code}: #{msg}" if $DEBUG
      return false
    end

    cert = ctx.current_cert
    self_signed = false
    ca = false
    pathlen = nil
    server_auth = true
    self_signed = (cert.subject.cmp(cert.issuer) == 0)

    # Check extensions whatever its criticality is. (sample)
    cert.extensions.each do |ex|
      case ex.oid
      when 'basicConstraints'
        /CA:(TRUE|FALSE), pathlen:(\d+)/ =~ ex.value
        ca = ($1 == 'TRUE')
        pathlen = $2.to_i
      when 'keyUsage'
        usage = ex.value.split(/\s*,\s*/)
        ca = usage.include?('Certificate Sign')
        server_auth = usage.include?('Key Encipherment')
      when 'extendedKeyUsage'
        usage = ex.value.split(/\s*,\s*/)
        server_auth = usage.include?('Netscape Server Gated Crypto')
      when 'nsCertType'
        usage = ex.value.split(/\s*,\s*/)
        ca = usage.include?('SSL CA')
        server_auth = usage.include?('SSL Server')
      end
    end

    if self_signed
      STDERR.puts 'self signing CA' if $DEBUG
      return true
    elsif ca
      STDERR.puts 'middle level CA' if $DEBUG
      return true
    elsif server_auth
      STDERR.puts 'for server authentication' if $DEBUG
      return true
    end

    return false
  end

private

  def change_notify
    @client.reset_all
  end
end


# HTTPAccess2::BasicAuth -- BasicAuth repository.
#
class BasicAuth # :nodoc:
  def initialize(client)
    @client = client
    @auth = {}
  end

  def set(uri, user_id, passwd)
    uri = uri.clone
    uri.path = uri.path.sub(/\/[^\/]*$/, '/')
    @auth[uri] = ["#{user_id}:#{passwd}"].pack('m').strip
    @client.reset_all
  end

  def get(uri)
    @auth.each do |realm_uri, cred|
      if ((realm_uri.host == uri.host) and
          (realm_uri.scheme == uri.scheme) and
          (realm_uri.port == uri.port) and
          uri.path.upcase.index(realm_uri.path.upcase) == 0)
        return cred
      end
    end
    nil
  end
end


# HTTPAccess2::Site -- manage a site(host and port)
#
class Site      # :nodoc:
  attr_accessor :scheme
  attr_accessor :host
  attr_reader :port

  def initialize(uri = nil)
    if uri
      @scheme = uri.scheme
      @host = uri.host
      @port = uri.port.to_i
    else
      @scheme = 'tcp'
      @host = '0.0.0.0'
      @port = 0
    end
  end

  def addr
    "#{@scheme}://#{@host}:#{@port.to_s}"
  end

  def port=(port)
    @port = port.to_i
  end

  def ==(rhs)
    if rhs.is_a?(Site)
      ((@scheme == rhs.scheme) and (@host == rhs.host) and (@port == rhs.port))
    else
      false
    end
  end

  def to_s
    addr
  end

  def inspect
    sprintf("#<%s:0x%x %s>", self.class.name, __id__, addr)
  end
end


# HTTPAccess2::Connection -- magage a connection(one request and response to it).
#
class Connection        # :nodoc:
  attr_accessor :async_thread

  def initialize(header_queue = [], body_queue = [])
    @headers = header_queue
    @body = body_queue
    @async_thread = nil
    @queue = Queue.new
  end

  def finished?
    if !@async_thread
      # Not in async mode.
      true
    elsif @async_thread.alive?
      # Working...
      false
    else
      # Async thread have been finished.
      @async_thread.join
      true
    end
  end

  def pop
    @queue.pop
  end

  def push(result)
    @queue.push(result)
  end

  def join
    unless @async_thread
      false
    else
      @async_thread.join
    end
  end
end


# HTTPAccess2::SessionManager -- manage several sessions.
#
class SessionManager    # :nodoc:
  attr_accessor :agent_name     # Name of this client.
  attr_accessor :from           # Owner of this client.

  attr_accessor :protocol_version       # Requested protocol version
  attr_accessor :chunk_size             # Chunk size for chunked request
  attr_accessor :debug_dev              # Device for dumping log for debugging
  attr_accessor :socket_sync            # Boolean value for Socket#sync

  # These parameters are not used now...
  attr_accessor :connect_timeout
  attr_accessor :connect_retry          # Maximum retry count.  0 for infinite.
  attr_accessor :send_timeout
  attr_accessor :receive_timeout
  attr_accessor :read_block_size

  attr_accessor :ssl_config

  def initialize
    @proxy = nil

    @agent_name = nil
    @from = nil

    @protocol_version = nil
    @debug_dev = nil
    @socket_sync = true
    @chunk_size = 4096

    @connect_timeout = 60
    @connect_retry = 1
    @send_timeout = 120
    @receive_timeout = 60       # For each read_block_size bytes
    @read_block_size = 8192

    @ssl_config = nil

    @sess_pool = []
    @sess_pool_mutex = Mutex.new
  end

  def proxy=(proxy)
    if proxy.nil?
      @proxy = nil
    else
      @proxy = Site.new(proxy)
    end
  end

  def query(req, proxy)
    req.body.chunk_size = @chunk_size
    dest_site = Site.new(req.header.request_uri)
    proxy_site = if proxy
        Site.new(proxy)
      else
        @proxy
      end
    sess = open(dest_site, proxy_site)
    begin
      sess.query(req)
    rescue
      sess.close
      raise
    end
    sess
  end

  def reset(uri)
    site = Site.new(uri)
    close(site)
  end

  def reset_all
    close_all
  end

  def keep(sess)
    add_cached_session(sess)
  end

private

  def open(dest, proxy = nil)
    sess = nil
    if cached = get_cached_session(dest)
      sess = cached
    else
      sess = Session.new(dest, @agent_name, @from)
      sess.proxy = proxy
      sess.socket_sync = @socket_sync
      sess.requested_version = @protocol_version if @protocol_version
      sess.connect_timeout = @connect_timeout
      sess.connect_retry = @connect_retry
      sess.send_timeout = @send_timeout
      sess.receive_timeout = @receive_timeout
      sess.read_block_size = @read_block_size
      sess.ssl_config = @ssl_config
      sess.debug_dev = @debug_dev
    end
    sess
  end

  def close_all
    each_sess do |sess|
      sess.close
    end
    @sess_pool.clear
  end

  def close(dest)
    if cached = get_cached_session(dest)
      cached.close
      true
    else
      false
    end
  end

  def get_cached_session(dest)
    cached = nil
    @sess_pool_mutex.synchronize do
      new_pool = []
      @sess_pool.each do |s|
        if s.dest == dest
          cached = s
        else
          new_pool << s
        end
      end
      @sess_pool = new_pool
    end
    cached
  end

  def add_cached_session(sess)
    @sess_pool_mutex.synchronize do
      @sess_pool << sess
    end
  end

  def each_sess
    @sess_pool_mutex.synchronize do
      @sess_pool.each do |sess|
        yield(sess)
      end
    end
  end
end


# HTTPAccess2::SSLSocketWrap
#
class SSLSocketWrap
  def initialize(socket, context, debug_dev = nil)
    unless SSLEnabled
      raise RuntimeError.new(
        "Ruby/OpenSSL module is required for https access.")
    end
    @context = context
    @socket = socket
    @ssl_socket = create_ssl_socket(@socket)
    @debug_dev = debug_dev
  end

  def ssl_connect
    @ssl_socket.connect
  end

  def post_connection_check(host)
    verify_mode = @context.verify_mode || OpenSSL::SSL::VERIFY_NONE
    if verify_mode == OpenSSL::SSL::VERIFY_NONE
      return
    elsif @ssl_socket.peer_cert.nil? and
        check_mask(verify_mode, OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT)
      raise OpenSSL::SSL::SSLError, "no peer cert"
    end
    hostname = host.host
    if @ssl_socket.respond_to?(:post_connection_check)
      @ssl_socket.post_connection_check(hostname)
    else
      @context.post_connection_check(@ssl_socket.peer_cert, hostname)
    end
  end

  def peer_cert
    @ssl_socket.peer_cert
  end

  def addr
    @socket.addr
  end

  def close
    @ssl_socket.close
    @socket.close
  end

  def closed?
    @socket.closed?
  end

  def eof?
    @ssl_socket.eof?
  end

  def gets(*args)
    str = @ssl_socket.gets(*args)
    @debug_dev << str if @debug_dev
    str
  end

  def read(*args)
    str = @ssl_socket.read(*args)
    @debug_dev << str if @debug_dev
    str
  end

  def <<(str)
    rv = @ssl_socket.write(str)
    @debug_dev << str if @debug_dev
    rv
  end

  def flush
    @ssl_socket.flush
  end

  def sync
    @ssl_socket.sync
  end

  def sync=(sync)
    @ssl_socket.sync = sync
  end

private

  def check_mask(value, mask)
    value & mask == mask
  end

  def create_ssl_socket(socket)
    ssl_socket = nil
    if OpenSSL::SSL.const_defined?("SSLContext")
      ctx = OpenSSL::SSL::SSLContext.new
      @context.set_context(ctx)
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ctx)
    else
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket)
      @context.set_context(ssl_socket)
    end
    ssl_socket
  end
end


# HTTPAccess2::DebugSocket -- debugging support
#
class DebugSocket < TCPSocket
  attr_accessor :debug_dev     # Device for logging.

  class << self
    def create_socket(host, port, debug_dev)
      debug_dev << "! CONNECT TO #{host}:#{port}\n"
      socket = new(host, port)
      socket.debug_dev = debug_dev
      socket.log_connect
      socket
    end

    private :new
  end

  def initialize(*args)
    super
    @debug_dev = nil
  end

  def log_connect
    @debug_dev << '! CONNECTION ESTABLISHED' << "\n"
  end

  def close
    super
    @debug_dev << '! CONNECTION CLOSED' << "\n"
  end

  def gets(*args)
    str = super
    @debug_dev << str if str
    str
  end

  def read(*args)
    str = super
    @debug_dev << str if str
    str
  end

  def <<(str)
    super
    @debug_dev << str
  end
end


# HTTPAccess2::Session -- manage http session with one site.
#   One or more TCP sessions with the site may be created.
#   Only 1 TCP session is live at the same time.
#
class Session   # :nodoc:

  class Error < StandardError   # :nodoc:
  end

  class InvalidState < Error    # :nodoc:
  end

  class BadResponse < Error     # :nodoc:
  end

  class KeepAliveDisconnected < Error   # :nodoc:
  end

  attr_reader :dest                     # Destination site
  attr_reader :src                      # Source site
  attr_accessor :proxy                  # Proxy site
  attr_accessor :socket_sync            # Boolean value for Socket#sync

  attr_accessor :requested_version      # Requested protocol version

  attr_accessor :debug_dev              # Device for dumping log for debugging

  # These session parameters are not used now...
  attr_accessor :connect_timeout
  attr_accessor :connect_retry
  attr_accessor :send_timeout
  attr_accessor :receive_timeout
  attr_accessor :read_block_size

  attr_accessor :ssl_config

  def initialize(dest, user_agent, from)
    @dest = dest
    @src = Site.new
    @proxy = nil
    @socket_sync = true
    @requested_version = nil

    @debug_dev = nil

    @connect_timeout = nil
    @connect_retry = 1
    @send_timeout = nil
    @receive_timeout = nil
    @read_block_size = nil

    @ssl_config = nil

    @user_agent = user_agent
    @from = from
    @state = :INIT

    @requests = []

    @status = nil
    @reason = nil
    @headers = []

    @socket = nil
  end

  # Send a request to the server
  def query(req)
    connect() if @state == :INIT
    begin
      timeout(@send_timeout) do
        set_header(req)
        req.dump(@socket)
        # flush the IO stream as IO::sync mode is false
        @socket.flush unless @socket_sync
      end
    rescue Errno::ECONNABORTED, Errno::ECONNRESET
      close
      raise KeepAliveDisconnected.new
    rescue
      if SSLEnabled and $!.is_a?(OpenSSL::SSL::SSLError)
        raise KeepAliveDisconnected.new
      elsif $!.is_a?(TimeoutError)
        close
        raise
      else
        raise
      end
    end

    @state = :META if @state == :WAIT
    @next_connection = nil
    @requests.push(req)
  end

  def close
    if !@socket.nil? and !@socket.closed?
      @socket.flush rescue nil  # try to rescue OpenSSL::SSL::SSLError: cf. #120
      @socket.close
    end
    @state = :INIT
  end

  def closed?
    @state == :INIT
  end

  def get_status
    version = status = reason = nil
    begin
      if @state != :META
        raise RuntimeError.new("get_status must be called at the beginning of a session.")
      end
      version, status, reason = read_header()
    rescue
      close
      raise
    end
    return version, status, reason
  end

  def get_header(&block)
    begin
      read_header() if @state == :META
    rescue
      close
      raise
    end
    if block
      @headers.each do |line|
        block.call(line)
      end
    else
      @headers
    end
  end

  def eof?
    if !@content_length.nil?
      @content_length == 0
    elsif @readbuf.length > 0
      false
    else
      @socket.closed? or @socket.eof?
    end
  end

  def get_data(&block)
    begin
      read_header() if @state == :META
      return nil if @state != :DATA
      unless @state == :DATA
        raise InvalidState.new('state != DATA')
      end
      data = nil
      if block
        until eof?
          begin
            timeout(@receive_timeout) do
              data = read_body()
            end
          rescue TimeoutError
            raise
          end
          block.call(data) if data
        end
        data = nil      # Calling with block returns nil.
      else
        begin
          timeout(@receive_timeout) do
            data = read_body()
          end
        rescue TimeoutError
          raise
        end
      end
    rescue
      close
      raise
    end
    if eof?
      if @next_connection
        @state = :WAIT
      else
        close
      end
    end
    data
  end

private

  LibNames = "(#{RCS_FILE}/#{RCS_REVISION}, #{RUBY_VERSION_STRING})"

  def set_header(req)
    req.version = @requested_version if @requested_version
    if @user_agent
      req.header.set('User-Agent', "#{@user_agent} #{LibNames}")
    end
    if @from
      req.header.set('From', @from)
    end
    req.header.set('Date', HTTP.http_date(Time.now))
  end

  # Connect to the server
  def connect
    site = @proxy || @dest
    begin
      retry_number = 0
      timeout(@connect_timeout) do
        @socket = create_socket(site)
        begin
          @src.host = @socket.addr[3]
          @src.port = @socket.addr[1]
        rescue SocketError
          # to avoid IPSocket#addr problem on Mac OS X 10.3 + ruby-1.8.1.
          # cf. [ruby-talk:84909], [ruby-talk:95827]
        end
        if @dest.scheme == 'https'
          @socket = create_ssl_socket(@socket)
          connect_ssl_proxy(@socket) if @proxy
          @socket.ssl_connect
          @socket.post_connection_check(@dest)
        end
        # Use Ruby internal buffering instead of passing data immediatly
        # to the underlying layer
        # => we need to to call explicitely flush on the socket
        @socket.sync = @socket_sync
      end
    rescue TimeoutError
      if @connect_retry == 0
        retry
      else
        retry_number += 1
        retry if retry_number < @connect_retry
      end
      close
      raise
    end

    @state = :WAIT
    @readbuf = ''
  end

  def create_socket(site)
    begin
      if @debug_dev
        DebugSocket.create_socket(site.host, site.port, @debug_dev)
      else
        TCPSocket.new(site.host, site.port)
      end
    rescue SystemCallError => e
      e.message << " (#{site.host}, ##{site.port})"
      raise
    end
  end

  # wrap socket with OpenSSL.
  def create_ssl_socket(raw_socket)
    SSLSocketWrap.new(raw_socket, @ssl_config, (DEBUG_SSL ? @debug_dev : nil))
  end

  def connect_ssl_proxy(socket)
    socket << sprintf("CONNECT %s:%s HTTP/1.1\r\n\r\n", @dest.host, @dest.port)
    parse_header(socket)
    unless @status == 200
      raise BadResponse.new(
        "connect to ssl proxy failed with status #{@status} #{@reason}")
    end
  end

  # Read status block.
  def read_header
    if @state == :DATA
      get_data {}
      check_state()
    end
    unless @state == :META
      raise InvalidState, 'state != :META'
    end
    parse_header(@socket)
    @content_length = nil
    @chunked = false
    @headers.each do |line|
      case line
      when /^Content-Length:\s+(\d+)/i
        @content_length = $1.to_i
      when /^Transfer-Encoding:\s+chunked/i
        @chunked = true
        @content_length = true  # how?
        @chunk_length = 0
      when /^Connection:\s+([\-\w]+)/i, /^Proxy-Connection:\s+([\-\w]+)/i
        case $1
        when /^Keep-Alive$/i
          @next_connection = true
        when /^close$/i
          @next_connection = false
        end
      else
        # Nothing to parse.
      end
    end

    # Head of the request has been parsed.
    @state = :DATA
    req = @requests.shift

    if req.header.request_method == 'HEAD'
      @content_length = 0
      if @next_connection
        @state = :WAIT
      else
        close
      end
    end
    @next_connection = false unless @content_length
    return [@version, @status, @reason]
  end

  StatusParseRegexp = %r(\AHTTP/(\d+\.\d+)\s+(\d+)(?:\s+([^\r\n]+))?\r?\n\z)
  def parse_header(socket)
    begin
      timeout(@receive_timeout) do
        begin
          initial_line = socket.gets("\n")
          if initial_line.nil?
            raise KeepAliveDisconnected.new
          end
          if StatusParseRegexp =~ initial_line
            @version, @status, @reason = $1, $2.to_i, $3
            @next_connection = HTTP.keep_alive_enabled?(@version)
          else
            @version = '0.9'
            @status = nil
            @reason = nil
            @next_connection = false
            @readbuf = initial_line
            break
          end
          @headers = []
          while true
            line = socket.gets("\n")
            unless line
              raise BadResponse.new('Unexpected EOF.')
            end
            line.sub!(/\r?\n\z/, '')
            break if line.empty?
            if line.sub!(/^\t/, '')
              @headers[-1] << line
            else
              @headers.push(line)
            end
          end
        end while (@version == '1.1' && @status == 100)
      end
    rescue TimeoutError
      raise
    end
  end

  def read_body
    if @chunked
      return read_body_chunked()
    elsif @content_length == 0
      return nil
    elsif @content_length
      return read_body_length()
    else
      if @readbuf.length > 0
        data = @readbuf
        @readbuf = ''
        return data
      else
        data = @socket.read(@read_block_size)
        data = nil if data.empty?       # Absorbing interface mismatch.
        return data
      end
    end
  end

  def read_body_length
    maxbytes = @read_block_size
    if @readbuf.length > 0
      data = @readbuf[0, @content_length]
      @readbuf[0, @content_length] = ''
      @content_length -= data.length
      return data
    end
    maxbytes = @content_length if maxbytes > @content_length
    data = @socket.read(maxbytes)
    if data
      @content_length -= data.length
    else
      @content_length = 0
    end
    return data
  end

  RS = "\r\n"
  def read_body_chunked
    if @chunk_length == 0
      until (i = @readbuf.index(RS))
        @readbuf << @socket.gets(RS)
      end
      i += 2
      @chunk_length = @readbuf[0, i].hex
      @readbuf[0, i] = ''
      if @chunk_length == 0
        @content_length = 0
        @socket.gets(RS)
        return nil
      end
    end
    while @readbuf.length < @chunk_length + 2
      @readbuf << @socket.read(@chunk_length + 2 - @readbuf.length)
    end
    data = @readbuf[0, @chunk_length]
    @readbuf[0, @chunk_length + 2] = ''
    @chunk_length = 0
    return data
  end

  def check_state
    if @state == :DATA
      if eof?
        if @next_connection
          if @requests.empty?
            @state = :WAIT
          else
            @state = :META
          end
        end
      end
    end
  end
end


end


HTTPClient = HTTPAccess2::Client
