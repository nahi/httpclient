# HTTPAccess2 - HTTP accessing library.
# Copyright (C) 2000, 2001, 2002, 2003 NAKAMURA, Hiroshi.
# 
# This module is copyrighted free software by NAKAMURA, Hiroshi.
# You can redistribute it and/or modify it under the same term as Ruby.
# 
# http-access2.rb is based on http-access.rb in http-access/0.0.4.  Some part
# of code in http-access.rb was recycled in http-access2.rb.  Those part is
# copyrighted by Maehashi-san who made and distribute http-access/0.0.4. Many
# thanks to Maehashi-san.


# Ruby standard library
require 'timeout'
require 'uri'
require 'socket'
require 'thread'

# Extra library
require 'http-access2/http'


module HTTPAccess2
  VERSION = '1.1'
  RUBY_VERSION_STRING = "ruby #{ RUBY_VERSION } (#{ RUBY_RELEASE_DATE }) [#{ RUBY_PLATFORM }]"
  s = %w$Id: http-access2.rb,v 1.15 2003/06/01 10:07:36 nahi Exp $
  RCS_FILE, RCS_REVISION = s[1][/.*(?=,v$)/], s[2]

  RS = "\r\n"
  FS = "\r\n\t"

  SSLEnabled = begin
      require 'openssl'
      true
    rescue LoadError
      false
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
  attr_reader :agent_name	# Name of this client.
  attr_reader :from		# Owner of this client.
  attr_accessor :proxy		# HTTP Proxy URI.
  attr_reader :debug_dev	# Device for logging.
  attr_reader :session_manager	# Session manager.
  attr_reader :ssl_config	# SSL configuration (if enabled).

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
  #   proxy		A String of HTTP proxy URL. ex. "http://proxy:8080"
  #   agent_name	A String for "User-Agent" HTTP request header.
  #   from		A String for "From" HTTP request header.
  #
  # DESCRIPTION
  #   Create an instance.
  #
  def initialize(proxy = nil, agent_name = nil, from = nil)
    @proxy = proxy
    @agent_name = agent_name
    @from = from
    @basic_auth = BasicAuth.new
    @debug_dev = nil
    @ssl_config = SSLConfig.new
    @session_manager = SessionManager.new
    @session_manager.agent_name = @agent_name
    @session_manager.from = @from
    @session_manager.ssl_config = @ssl_config
  end

  # SYNOPSIS
  #   Client#debug_dev=(dev)
  #
  # ARGS
  #   dev	Device for debugging.  nil for 'no debugging device'
  #
  # DEBT
  #   dev must respond to '<<' method.
  #
  # DESCRIPTION
  #   Set debug device.  Messages for debugging is dumped to the device.
  #
  def debug_dev=(dev)
    @debug_dev = dev
    @session_manager.debug_dev = dev
  end

  def set_basic_auth(uri, user_id, passwd)
    unless uri.is_a?(URI)
      uri = URI.parse(uri)
    end
    @basic_auth.set(uri, user_id, passwd)
  end

  # SYNOPSIS
  #   Client#get_content(uri, query = nil, extra_header = {}, &block = nil)
  #
  # ARGS
  #   uri	an_URI or a_string of uri to connect.
  #   query	a_hash or an_array of query part.  e.g. { "a" => "b" }.
  #   		Give an array to pass multiple value like
  #   		[["a" => "b"], ["a" => "c"]].
  #   extra_header
  #   		a_hash of extra headers like { "SOAPAction" => "urn:foo" }.
  #   &block	Give a block to get chunked message-body of response like
  #   		get_content(uri) { |chunked_body| ... }
  #   		Size of each chunk may not be the same.
  #
  # DESCRIPTION
  #   Get a_sring of message-body of response.
  #
  def get_content(uri, query = nil, extra_header = {}, &block)
    retry_number = 0
    while retry_number < 10
      res = get(uri, query, extra_header, &block)
      case res.status
      when HTTP::Status::OK
	return res.content
      when HTTP::Status::MOVED_PERMANENTLY, HTTP::Status::MOVED_TEMPORARILY
	uri = res.header['location'][0]
	query = nil
	retry_number += 1
	puts "Redirect to: #{ uri }" if $DEBUG
      else
	raise RuntimeError.new("Unexpected response: #{ res.header.inspect }")
      end
    end
    raise RuntimeError.new("Retry count exceeded.")
  end

  def head(uri, query = nil, extra_header = {})
    request('HEAD', uri, query, nil, extra_header)
  end

  def get(uri, query = nil, extra_header = {}, &block)
    request('GET', uri, query, nil, extra_header, &block)
  end

  def post(uri, body = nil, extra_header = {}, &block)
    request('POST', uri, nil, body, extra_header, &block)
  end

  def put(uri, body = nil, extra_header = {}, &block)
    request('PUT', uri, nil, body, extra_header, &block)
  end

  def delete(uri, extra_header = {}, &block)
    request('DELETE', uri, nil, nil, extra_header, &block)
  end

  def options(uri, extra_header = {}, &block)
    request('OPTIONS', uri, nil, nil, extra_header, &block)
  end

  def trace(uri, query = nil, body = nil, extra_header = {}, &block)
    request('TRACE', uri, query, body, extra_header, &block)
  end

  def request(method, uri, query = nil, body = nil, extra_header = {}, &block)
    @debug_dev << "= Request\n\n" if @debug_dev
    conn = Connection.new
    begin
      req = create_request(method, uri, query, body, extra_header)
      sess = @session_manager.query(req, @proxy)
      @debug_dev << "\n\n= Response\n\n" if @debug_dev
      do_get_block(sess, conn, &block)
    rescue Session::KeepAliveDisconnected
      # Try again.
      req = create_request(method, uri, query, body, extra_header)
      sess = @session_manager.query(req, @proxy)
      @debug_dev << "\n\n= Response\n\n" if @debug_dev
      do_get_block(sess, conn, &block)
    end
    conn.pop
  end

  # Async interface.

  def head_async(uri, query = nil, extra_header = {})
    request_async('HEAD', uri, query, nil, extra_header)
  end

  def get_async(uri, query = nil, extra_header = {})
    request_async('GET', uri, query, nil, extra_header)
  end

  def post_async(uri, body = nil, extra_header = {})
    request_async('POST', uri, nil, body, extra_header)
  end

  def put_async(uri, body = nil, extra_header = {})
    request_async('PUT', uri, nil, body, extra_header)
  end

  def delete_async(uri, extra_header = {})
    request_async('DELETE', uri, nil, nil, extra_header)
  end

  def options_async(uri, extra_header = {})
    request_async('OPTIONS', uri, nil, nil, extra_header)
  end

  def trace_async(uri, query = nil, body = nil, extra_header = {})
    request_async('TRACE', uri, query, body, extra_header)
  end

  def request_async(method, uri, query = nil, body = nil, extra_header = {})
    @debug_dev << "= Request\n\n" if @debug_dev
    req = create_request(method, uri, query, body, extra_header)
    response_conn = Connection.new
    t = Thread.new(response_conn) { |conn|
      sess = @session_manager.query(req, @proxy)
      @debug_dev << "\n\n= Response\n\n" if @debug_dev
      begin
	do_get_stream(sess, conn)
      rescue Session::KeepAliveDisconnected
       	# Try again.
	req = create_request(method, uri, query, body, extra_header)
	sess = @session_manager.query(req, @proxy)
	do_get_stream(sess, conn)
      end
    }
    response_conn.async_thread = t
    response_conn
  end

  ##
  # Multiple call interface.

  # ???

  ##
  # Management interface.

  def reset(uri)
    @session_manager.reset(uri)
  end

private

  def create_request(method, uri, query, body, extra_header)
    if extra_header.is_a?(Hash)
      extra_header = extra_header.to_a
    end
    unless uri.is_a?(URI)
      uri = URI.parse(uri)
    end
    cred = @basic_auth.get(uri)
    if cred
      extra_header << ['Authorization', "Basic " << cred]
    end
    req = HTTP::Message.new_request(method, uri, query, body, @proxy)
    extra_header.each do |key, value|
      req.header.set(key, value)
    end
    req
  end

  # !! CAUTION !!
  #   Method 'do_get*' runs under MT conditon. Be careful to change.
  def do_get_block(sess, conn, &block)
    content = ''
    res = HTTP::Message.new_response(content)
    do_get_header(sess, conn, res)
    sess.get_data() do |str|
      block.call(str) if block
      content << str
    end
    @session_manager.keep(sess) unless sess.closed?
  end

  def do_get_stream(sess, conn)
    piper, pipew = IO.pipe
    res = HTTP::Message.new_response(piper)
    do_get_header(sess, conn, res)
    sess.get_data() do |str|
      pipew.syswrite(str)
    end
    pipew.close
    @session_manager.keep(sess) unless sess.closed?
  end

  def do_get_header(sess, conn, res)
    res.version, res.status, res.reason = sess.get_status
    sess.get_header().each do |line|
      unless /^([^:]+)\s*:\s*(.*)$/ =~ line
	raise RuntimeError.new("Unparsable header: '#{ line }'.") if $DEBUG
      end
      res.header.set($1, $2)
    end
    conn.push(res)
  end
end


# HTTPAccess2::SSLConfig -- SSL configuration of a client.
#
class SSLConfig	# :nodoc:
  attr_reader :client_cert
  attr_reader :client_key
  attr_reader :trust_ca_file
  attr_reader :trust_ca_path

  attr_accessor :verify_mode
  attr_accessor :verify_depth
  attr_accessor :verify_callback

  attr_accessor :timeout

  def initialize
    return unless SSLEnabled
    @client_cert = @client_key = nil
    @trust_ca_file = @trust_ca_path = nil
    @verify_mode = OpenSSL::SSL::VERIFY_PEER |
      OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    @verify_depth = 3
    @verify_callback = nil
    @dest = nil
    @timeout = nil
  end

  def create_context(dest)
    duped = self.dup
    duped.dest = dest
    duped
  end

  def set_client_cert_file(cert_file, key_file)
    @client_cert = OpenSSL::X509::Certificate.new(File.open(cert_file).read)
    @client_key = OpenSSL::X509::PKey.new(File.open(key_file).read)
  end

  def set_trust_ca(trust_ca_file_or_hashed_dir)
    if FileTest.directory?(trust_ca_file_or_hashed_dir)
      @trust_ca_file = nil
      @trust_ca_path = trust_ca_file_or_hashed_dir
    else
      @trust_ca_file = trust_ca_file_or_hashed_dir
      @trust_ca_path = nil
    end
  end

  def set_context(ctx)
    ctx.cert = @client_cert
    ctx.key = @client_key
    ctx.ca_file = @trust_ca_file
    ctx.ca_path = @trust_ca_path
    ctx.verify_mode = @verify_mode
    ctx.verify_depth = @verify_depth
    ctx.verify_callback = @verify_callback || method(:default_verify_callback)
    ctx.timeout = @timeout
  end

protected

  def dest=(dest)
    @dest = dest
  end

private

  # Does not check CRL/ARL.
  # Does not check keyUsage.
  # Does not check criticality of extentions.
  def default_verify_callback(ok, store)
    unless ok
      code = store.verify_status
      msg = store.verify_message
      depth = store.verify_depth
      STDERR.puts "at depth #{ depth } - #{ code }: #{ msg }" if $DEBUG
      return false
    end

    cert = store.cert
    if (cert.subject.cmp(cert.issuer) == 0)
      STDERR.puts 'self signing CA' if $DEBUG
      return true
    end

    basic_constraints = cert.extensions.find { |ext|
	ext.oid == 'basicConstraints'
      }
    if basic_constraints && /CA:TRUE/ =~ basic_constraints.value
      STDERR.puts 'middle level CA' if $DEBUG
      return true
    end

    # End Entity(CA:FALSE)
    cn = cert.subject.to_a.find { |rdn| rdn[0] == 'CN' }
    unless cn[1] == @dest.host
      STDERR.puts "CN does not match.  cert:#{ cn[1] }, connected:#{ @dest.host }" if $DEBUG
      return false
    end

    true
  end
end


# HTTPAccess2::BasicAuth -- BasicAuth repository.
#
class BasicAuth	# :nodoc:
  def initialize
    @auth = {}
  end

  def set(uri, user_id, passwd)
    uri = uri.clone
    uri.path = uri.path.sub(/\/[^\/]*$/, '/')
    @auth[uri] = ["#{ user_id }:#{ passwd }"].pack('m').strip
  end

  def get(uri)
    @auth.each do |realm_uri, cred|
      if ((realm_uri.host == uri.host) and
	  (realm_uri.scheme == uri.scheme) and
	  (realm_uri.port == uri.port) and
	  uri.path.index(realm_uri.path) == 0)
	return cred
      end
    end
    nil
  end
end


# HTTPAccess2::Site -- manage a site(host and port)
#
class Site	# :nodoc:
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
    "#{ @scheme }://#{ @host }:#{ @port.to_s }"
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
end


# HTTPAccess2::Connection -- magage a connection(one request and response to it).
#
class Connection	# :nodoc:
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
class SessionManager	# :nodoc:
  attr_accessor :agent_name	# Name of this client.
  attr_accessor :from		# Owner of this client.

  attr_accessor :protocol_version	# Requested protocol version
  attr_accessor :chunk_size		# Chunk size for chunked request
  attr_accessor :debug_dev		# Device for dumping log for debugging

  # These parameters are not used now...
  attr_accessor :connect_timeout
  attr_accessor :connect_retry		# Maximum retry count.  0 for infinite.
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
    @chunk_size = 4096

    @connect_timeout = 60
    @connect_retry = 1
    @send_timeout = 120
    @receive_timeout = 60	# For each read_block_size bytes...
    @read_block_size = 4096

    @ssl_config = nil

    @sess_pool = []
    @sess_pool_mutex = Mutex.new
  end

  def proxy=(proxy_str)
    unless proxy_str
      @proxy = nil 
      return
    end
    @proxy = Site.new(URI.parse(proxy_str))
  end

  def query(req, proxy_str)
    req.body.chunk_size = @chunk_size
    dest_site = Site.new(req.header.request_uri)
    proxy_site = if proxy_str
  	Site.new(URI.parse(proxy_str))
      else
	@proxy
      end
    sess = open(dest_site, proxy_site)
    begin
      sess.query(req)
    rescue
      close(dest_site)
      raise
    end

    sess
  end

  def reset(uri)
    unless uri.is_a?(URI)
      uri = URI.parse(uri.to_s)
    end
    site = Site.new(uri)
    close(site)
  end

  def keep(sess)
    add_cached_session(sess)
  end

private

  def open(dest, proxy = nil)
    sess = nil
    if (cached = get_cached_session(dest))
      sess = cached
    else
      sess = Session.new(dest, @agent_name, @from)
      sess.proxy = proxy
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

  def close(dest)
    if (cached = get_cached_session(dest))
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
end


# HTTPAccess2::SSLSocketWrap
#
class SSLSocketWrap
  def initialize(socket, context)
    unless SSLEnabled
      raise RuntimeError.new("Ruby/OpenSSL module is required for https access.")
    end
    @context = context
    @socket = socket
    @ssl_socket = create_ssl_socket(@socket)
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
    @ssl_socket.gets(*args)
  end

  def read(*args)
    @ssl_socket.read(*args)
  end

  def <<(str)
    @ssl_socket.write(str)
  end

private

  def create_ssl_socket(socket)
    ssl_socket = nil
    if OpenSSL::SSL.const_defined?("SSLContext")
      ctx = OpenSSL::SSL::SSLContext.new
      @context.set_context(ctx)
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ctx)
    else
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket)
      @context.set_context(ctx)
    end
    ssl_socket.connect
    ssl_socket
  end
end


# HTTPAccess2::DebugSocket -- debugging support
#
class DebugSocket < TCPSocket
  attr_accessor :debug_dev     # Device for logging.

  class << self
    def create_socket(host, port, debug_dev)
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
    @debug_dev << str
    str
  end

  def read(*args)
    str = super
    @debug_dev << str
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
class Session	# :nodoc:

  class Error < StandardError	# :nodoc:
  end

  class InvalidState < Error	# :nodoc:
  end

  class BadResponse < Error	# :nodoc:
  end

  class KeepAliveDisconnected < Error	# :nodoc:
  end

  attr_reader :dest			# Destination site
  attr_reader :src			# Source site
  attr_accessor :proxy			# Proxy site

  attr_accessor :requested_version	# Requested protocol version

  attr_accessor :debug_dev		# Device for dumping log for debugging

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
    @requested_version = VERSION

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
      end
    rescue Errno::ECONNABORTED
      close
      raise KeepAliveDisconnected.new
    rescue
      if SSLEnabled and $!.is_a?(OpenSSL::SSL::Error)
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
    unless @socket.nil?
      @socket.close unless @socket.closed?
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
    if @content_length == 0
      true
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
	data = nil	# Calling with block returns nil.
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

  LibNames = "(#{ RCS_FILE }/#{ RCS_REVISION }, #{ RUBY_VERSION_STRING })"

  def set_header(req)
    if @user_agent
      req.header.set('User-Agent', "#{ @user_agent } #{ LibNames }")
    end
    if @from
      req.header.set('From', @from)
    end
    req.header.set('Date', Time.now)
  end

  # Connect to the server
  def connect
    site = @proxy || @dest
    begin
      retry_number = 0
      timeout(@connect_timeout) do
	@socket = if @debug_dev	
	    DebugSocket.create_socket(site.host, site.port, @debug_dev)
	  else
	    TCPSocket.new(site.host, site.port)
	  end
	@src.host = @socket.addr[3]
	@src.port = @socket.addr[1]
	if @dest.scheme == 'https'
	  # wrap socket with OpenSSL.
	  context = @ssl_config.create_context(@dest)
	  @socket = SSLSocketWrap.new(@socket, context)
	end
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

  # Read status block.
  StatusParseRegexp = %r(\AHTTP/(\d+\.\d+)\s+(\d+)(?:\s+(.*))?#{ RS }\z)
  def read_header
    if @state == :DATA
      get_data {}
      check_state()
    end
    unless @state == :META
      raise InvalidState, 'state != :META'
    end

    begin
      timeout(@receive_timeout) do
	begin
	  @status_line = @socket.gets(RS)
	  if @status_line.nil?
	    raise KeepAliveDisconnected.new
	  end
	  StatusParseRegexp =~ @status_line
	  unless $1
	    raise BadResponse.new(@status_line)
	  end
	  @version, @status, @reason = $1, $2.to_i, $3
	  @next_connection = if HTTP.keep_alive_enabled?(@version)
	      true
	    else
	      false
	    end

	  @headers = []
	  until ((line = @socket.gets(RS)) == RS)
	    unless line
	      raise BadResponse.new('Unexpected EOF.')
	    end
	    line.sub!(/#{ RS }\z/, '')
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
	data = nil if data.empty?	# Absorbing interface mismatch.
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

  ChunkDelimiter = "0#{ RS }"
  ChunkTrailer = "0#{ RS }#{ RS }"
  def read_body_chunked
    if @chunk_length == 0
      until (i = @readbuf.index(RS))
	@readbuf << @socket.gets(RS)
      end
      i += 2
      if @readbuf[0, i] == ChunkDelimiter
	@content_length = 0
	unless @readbuf[0, 5] == ChunkTrailer
	  @readbuf << @socket.gets(RS)
	end
	@readbuf[0, 5] = ''
	return nil
      end
      @chunk_length = @readbuf[0, i].hex
      @readbuf[0, i] = ''
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
