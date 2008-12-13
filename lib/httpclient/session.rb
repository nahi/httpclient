# HTTPClient - HTTP client library.
# Copyright (C) 2000-2008  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.

# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.

# httpclient/session.rb is based on http-access.rb in http-access/0.0.4.
# Some part of code in http-access.rb was recycled in httpclient.rb.
# Those part is copyrighted by Maehashi-san.


# Ruby standard library
require 'socket'
require 'thread'
require 'stringio'

# Extra library
require 'httpclient/timeout'
require 'httpclient/ssl_config'
require 'httpclient/http'


class HTTPClient


  DEBUG_SSL = true


  # HTTPClient::Site -- manage a site(host and port)
  #
  class Site
    attr_accessor :scheme
    attr_accessor :host
    attr_reader :port

    def initialize(uri = nil)
      if uri
        @uri = uri
        @scheme = uri.scheme
        @host = uri.host
        @port = uri.port.to_i
      else
        @uri = nil
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
      rhs.is_a?(Site) and (@scheme == rhs.scheme) and (@host == rhs.host) and (@port == rhs.port)
    end

    def eql?(rhs)
      self == rhs
    end

    def hash
      [@scheme, @host, @port].hash
    end

    def to_s
      addr
    end

    def inspect
      sprintf("#<%s:0x%x %s>", self.class.name, __id__, @uri || addr)
    end
  end


  # HTTPClient::SessionManager -- manage several sessions.
  #
  class SessionManager
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

    attr_reader :test_loopback_http_response

    def initialize(client)
      @client = client

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
      @read_block_size = 1024 * 16 # follows net/http change in 1.8.7

      @ssl_config = nil
      @test_loopback_http_response = []

      @sess_pool = []
      @sess_pool_mutex = Mutex.new
    end

    def query(req, proxy)
      req.body.chunk_size = @chunk_size
      dest_site = Site.new(req.header.request_uri)
      proxy_site = proxy ? Site.new(proxy) : nil
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
        sess = Session.new(@client, dest, @agent_name, @from)
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
        sess.test_loopback_http_response = @test_loopback_http_response
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


  # HTTPClient::SSLSocketWrap
  #
  class SSLSocketWrap
    def initialize(socket, context, debug_dev = nil)
      unless SSLEnabled
        raise ConfigurationError.new('Ruby/OpenSSL module is required')
      end
      @context = context
      @socket = socket
      @ssl_socket = create_openssl_socket(@socket)
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
        raise OpenSSL::SSL::SSLError.new('no peer cert')
      end
      hostname = host.host
      if @ssl_socket.respond_to?(:post_connection_check) and RUBY_VERSION > "1.8.4"
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

    def create_openssl_socket(socket)
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


  module SocketWrap
    def initialize(socket, *args)
      super(*args)
      @socket = socket
    end

    def addr
      @socket.addr
    end

    def close
      @socket.close
    end

    def closed?
      @socket.closed?
    end

    def eof?
      @socket.eof?
    end

    def gets(*args)
      @socket.gets(*args)
    end

    def read(*args)
      @socket.read(*args)
    end

    def <<(str)
      @socket << str
    end

    def flush
      @socket.flush
    end

    def sync
      @socket.sync
    end

    def sync=(sync)
      @socket.sync = sync
    end
  end


  # HTTPClient::DebugSocket -- debugging support
  #
  module DebugSocket
    extend SocketWrap

    def debug_dev=(debug_dev)
      @debug_dev = debug_dev
    end

    def close
      super
      debug("! CONNECTION CLOSED\n")
    end

    def gets(*args)
      str = super
      debug(str)
      str
    end

    def read(*args)
      str = super
      debug(str)
      str
    end

    def <<(str)
      super
      debug(str)
    end

  private

    def debug(str)
      @debug_dev << str if @debug_dev
    end
  end


  # HTTPClient::LoopBackSocket -- dummy socket for dummy response
  #
  class LoopBackSocket
    include SocketWrap

    def initialize(host, port, response)
      super(StringIO.new(response))
      @host = host
      @port = port
    end

    def addr
      [nil, @port, @host, @host]
    end

    def <<(str)
      # ignored
    end
  end


  # HTTPClient::Session -- manage http session with one site.
  #   One or more TCP sessions with the site may be created.
  #   Only 1 TCP session is live at the same time.
  #
  class Session
    include HTTPClient::Timeout

    class Error < StandardError
    end

    class InvalidState < Error
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
    attr_reader :ssl_peer_cert
    attr_accessor :test_loopback_http_response

    def initialize(client, dest, user_agent, from)
      @client = client
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
      @ssl_peer_cert = nil

      @test_loopback_http_response = nil

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
      connect if @state == :INIT
      begin
        timeout(@send_timeout) do
          set_header(req)
          req.dump(@socket)
          # flush the IO stream as IO::sync mode is false
          @socket.flush unless @socket_sync
        end
      rescue Errno::ECONNABORTED, Errno::ECONNRESET, Errno::EPIPE
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
        # @socket.flush may block when it the socket is already closed by
        # foreign host and the client runs under MT-condition.
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
          raise InvalidState.new("get_status must be called at the beginning of a session")
        end
        version, status, reason = read_header
      rescue
        close
        raise
      end
      return version, status, reason
    end

    def get_header(&block)
      begin
        read_header if @state == :META
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
        read_header if @state == :META
        return nil if @state != :DATA
        unless @state == :DATA
          raise InvalidState.new('state != DATA')
        end
        data = nil
        if block
          while true
            begin
              timeout(@receive_timeout) do
                data = read_body
              end
            rescue TimeoutError
              raise
            end
            block.call(data) if data
            break if eof?
          end
          data = nil      # Calling with block returns nil.
        else
          begin
            timeout(@receive_timeout) do
              data = read_body
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

    def set_header(req)
      req.version = @requested_version if @requested_version
      if @user_agent
        req.header.set('User-Agent', "#{@user_agent} #{LIB_NAME}")
      end
      if @from
        req.header.set('From', @from)
      end
      req.header.set('Date', HTTP.http_date(Time.now))
    end

    # Connect to the server
    def connect
      site = @proxy || @dest
      retry_number = 0
      begin
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
            connect_ssl_proxy(@socket, @dest) if @proxy
            @socket.ssl_connect
            @socket.post_connection_check(@dest)
            @ssl_peer_cert = @socket.peer_cert
          end
          # Use Ruby internal buffering instead of passing data immediatly
          # to the underlying layer
          # => we need to to call explicitely flush on the socket
          @socket.sync = @socket_sync
        end
      rescue RetryableResponse
        retry_number += 1
        if retry_number < @protocol_retry_count
          retry
        end
        raise BadResponse.new("connect to the server failed with status #{@status} #{@reason}")
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
      socket = nil
      begin
        @debug_dev << "! CONNECT TO #{site.host}:#{site.port}\n" if @debug_dev
        if str = @test_loopback_http_response.shift
          socket = LoopBackSocket.new(site.host, site.port, str)
        else
          socket = TCPSocket.new(site.host, site.port)
        end
        if @debug_dev
          @debug_dev << "! CONNECTION ESTABLISHED\n"
          socket.extend(DebugSocket)
          socket.debug_dev = @debug_dev
        end
      rescue SystemCallError => e
        e.message << " (#{site})"
        raise
      rescue SocketError => e
        e.message << " (#{site})"
        raise
      end
      socket
    end

    # wrap socket with OpenSSL.
    def create_ssl_socket(raw_socket)
      SSLSocketWrap.new(raw_socket, @ssl_config, (DEBUG_SSL ? @debug_dev : nil))
    end

    def connect_ssl_proxy(socket, uri)
      req = HTTP::Message.new_connect_request(uri, "#{@dest.host}:#{@dest.port}")
      @client.request_filter.each do |filter|
        filter.filter_request(req)
      end
      set_header(req)
      req.dump(@socket)
      @socket.flush unless @socket_sync
      res = HTTP::Message.new_response('')
      parse_header(@socket)
      res.version, res.status, res.reason = @version, @status, @reason
      @headers.each do |line|
        unless /^([^:]+)\s*:\s*(.*)$/ =~ line
          raise BadResponse.new("unparsable header: #{line}", res) if $DEBUG
        end
        res.header.set($1, $2)
      end
      commands = @client.request_filter.collect { |filter|
        filter.filter_response(req, res)
      }
      if commands.find { |command| command == :retry }
        raise RetryableResponse.new
      end
      unless @status == 200
        raise BadResponse.new("connect to ssl proxy failed with status #{@status} #{@reason}", res)
      end
    end

    # Read status block.
    def read_header
      if @state == :DATA
        get_data {}
        check_state
      end
      unless @state == :META
        raise InvalidState, 'state != :META'
      end
      parse_header(@socket)
      @content_length = 0
      @chunked = false
      @headers.each do |line|
        case line
        when /^Content-Length:\s+(\d+)/i
          @content_length = $1.to_i
        when /^Transfer-Encoding:\s+chunked/i
          @chunked = true
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

    StatusParseRegexp = %r(\AHTTP/(\d+\.\d+)\s+(\d\d\d)\s*([^\r\n]+)?\r?\n\z)
    def parse_header(socket)
      begin
        timeout(@receive_timeout) do
          begin
            initial_line = socket.gets("\n")
            if initial_line.nil?
              raise KeepAliveDisconnected.new
            end
            if StatusParseRegexp !~ initial_line
              @version = '0.9'
              @status = nil
              @reason = nil
              @next_connection = false
              @readbuf = initial_line
              break
	    end
	    @version, @status, @reason = $1, $2.to_i, $3
	    @next_connection = HTTP.keep_alive_enabled?(@version)
            @headers = []
            while true
              line = socket.gets("\n")
              unless line
                raise BadResponse.new('unexpected EOF')
              end
              line.chomp!
              break if line.empty?
              if line[0] == ?\t
                @headers[-1] << line[1..-1]
              else
                @headers << line
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
        return read_body_chunked
      elsif @content_length == 0
        return nil
      elsif @content_length
        return read_body_length
      else
        if @readbuf.length > 0
          data = @readbuf
          @readbuf = ''
          return data
        else
          data = @socket.read(@read_block_size)
          data = nil if data and data.empty?       # Absorbing interface mismatch.
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
