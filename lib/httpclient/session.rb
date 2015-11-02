# HTTPClient - HTTP client library.
# Copyright (C) 2000-2009  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.
#
# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.
#
# httpclient/session.rb is based on http-access.rb in http-access/0.0.4.  Some
# part of it is copyrighted by Maebashi-san who made and published
# http-access/0.0.4.  http-access/0.0.4 did not include license notice but when
# I asked Maebashi-san he agreed that I can redistribute it under the same terms
# of Ruby.  Many thanks to Maebashi-san.


require 'socket'
require 'thread'
require 'stringio'
require 'zlib'

require 'httpclient/timeout' # TODO: remove this once we drop 1.8 support
require 'httpclient/ssl_config'
require 'httpclient/http'


class HTTPClient


  # Represents a Site: protocol scheme, host String and port Number.
  class Site
    # Protocol scheme.
    attr_accessor :scheme
    # Host String.
    attr_accessor :host
    alias hostname host
    # Port number.
    attr_accessor :port

    # Creates a new Site based on the given URI.
    def initialize(uri = nil)
      if uri
        @scheme = uri.scheme || 'tcp'
        @host = uri.hostname || '0.0.0.0'
        @port = uri.port.to_i
      else
        @scheme = 'tcp'
        @host = '0.0.0.0'
        @port = 0
      end
    end

    # Returns address String.
    def addr
      "#{@scheme}://#{@host}:#{@port.to_s}"
    end

    # Returns true is scheme, host and port are '=='
    def ==(rhs)
      (@scheme == rhs.scheme) and (@host == rhs.host) and (@port == rhs.port)
    end

    # Same as ==.
    def eql?(rhs)
      self == rhs
    end

    def hash # :nodoc:
      [@scheme, @host, @port].hash
    end

    def to_s # :nodoc:
      addr
    end
    
    # Returns true if scheme, host and port of the given URI matches with this.
    def match(uri)
      (@scheme == uri.scheme) and (@host == uri.host) and (@port == uri.port.to_i)
    end

    def inspect # :nodoc:
      sprintf("#<%s:0x%x %s>", self.class.name, __id__, addr)
    end

    EMPTY = Site.new.freeze
  end


  # Manages sessions for a HTTPClient instance.
  class SessionManager
    # Name of this client.  Used for 'User-Agent' header in HTTP request.
    attr_accessor :agent_name
    # Owner of this client.  Used for 'From' header in HTTP request.
    attr_accessor :from

    # Requested protocol version
    attr_accessor :protocol_version
    # Chunk size for chunked request
    attr_accessor :chunk_size
    # Device for dumping log for debugging
    attr_accessor :debug_dev
    # Boolean value for Socket#sync
    attr_accessor :socket_sync

    attr_accessor :connect_timeout
    # Maximum retry count.  0 for infinite.
    attr_accessor :connect_retry
    attr_accessor :send_timeout
    attr_accessor :receive_timeout
    attr_accessor :keep_alive_timeout
    attr_accessor :read_block_size
    attr_accessor :protocol_retry_count

    # Local address to bind local side of the socket to
    attr_accessor :socket_local

    attr_accessor :ssl_config

    attr_reader :test_loopback_http_response

    attr_accessor :transparent_gzip_decompression

    def initialize(client)
      @client = client
      @proxy = client.proxy

      @agent_name = nil
      @from = nil

      @protocol_version = nil
      @debug_dev = client.debug_dev
      @socket_sync = true
      @chunk_size = ::HTTP::Message::Body::DEFAULT_CHUNK_SIZE

      @connect_timeout = 60
      @connect_retry = 1
      @send_timeout = 120
      @receive_timeout = 60        # For each read_block_size bytes
      @keep_alive_timeout = 15     # '15' is from Apache 2 default
      @read_block_size = 1024 * 16 # follows net/http change in 1.8.7
      @protocol_retry_count = 5

      @ssl_config = nil
      @test_loopback_http_response = []

      @transparent_gzip_decompression = false
      @socket_local = Site.new

      @sess_pool = {}
      @sess_pool_mutex = Mutex.new
      @sess_pool_last_checked = Time.now
    end

    def proxy=(proxy)
      if proxy.nil?
        @proxy = nil
      else
        @proxy = Site.new(proxy)
      end
    end

    def query(req, via_proxy)
      req.http_body.chunk_size = @chunk_size if req.http_body
      sess = get_session(req, via_proxy)
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

    # assert: sess.last_used must not be nil
    def keep(sess)
      add_cached_session(sess)
    end

  private

    # TODO: create PR for webmock's httpclient adapter to use get_session
    # instead of open so that we can remove duplicated Site creation for
    # each session.
    def get_session(req, via_proxy = false)
      uri = req.header.request_uri
      if uri.scheme.nil?
        raise ArgumentError.new("Request URI must have schema. Possibly add 'http://' to the request URI?")
      end
      site = Site.new(uri)
      if cached = get_cached_session(site)
        cached
      else
        open(uri, via_proxy)
      end
    end

    def open(uri, via_proxy = false)
      site = Site.new(uri)
      sess = Session.new(@client, site, @agent_name, @from)
      sess.proxy = via_proxy ? @proxy : nil
      sess.socket_sync = @socket_sync
      sess.requested_version = @protocol_version if @protocol_version
      sess.connect_timeout = @connect_timeout
      sess.connect_retry = @connect_retry
      sess.send_timeout = @send_timeout
      sess.receive_timeout = @receive_timeout
      sess.read_block_size = @read_block_size
      sess.protocol_retry_count = @protocol_retry_count
      sess.ssl_config = @ssl_config
      sess.debug_dev = @debug_dev
      sess.socket_local = @socket_local
      sess.test_loopback_http_response = @test_loopback_http_response
      sess.transparent_gzip_decompression = @transparent_gzip_decompression
      sess
    end

    def close_all
      @sess_pool_mutex.synchronize do
        @sess_pool.each do |site, pool|
          pool.each do |sess|
            sess.close
          end
        end
      end
      @sess_pool.clear
    end

    # This method might not work as you expected...
    def close(dest)
      if cached = get_cached_session(Site.new(dest))
        cached.close
        true
      else
        false
      end
    end

    def get_cached_session(site)
      if Thread.current[:HTTPClient_AcquireNewConnection]
        return nil
      end
      @sess_pool_mutex.synchronize do
        now = Time.now
        if now > @sess_pool_last_checked + @keep_alive_timeout
          scrub_cached_session(now)
          @sess_pool_last_checked = now
        end
        if pool = @sess_pool[site]
          pool.each_with_index do |sess, idx|
            if valid_session?(sess, now)
              return pool.slice!(idx)
            end
          end
        end
      end
      nil
    end

    def scrub_cached_session(now)
      @sess_pool.each do |site, pool|
        pool.replace(pool.select { |sess|
          if valid_session?(sess, now)
            true
          else
            sess.close # close & remove from the pool
            false
          end
        })
      end
    end

    def valid_session?(sess, now)
      (now <= sess.last_used + @keep_alive_timeout)
    end

    def add_cached_session(sess)
      @sess_pool_mutex.synchronize do
        (@sess_pool[sess.dest] ||= []).unshift(sess)
      end
    end
  end


  # Wraps up OpenSSL::SSL::SSLSocket and offers debugging features.
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

    def ssl_connect(hostname = nil)
      if hostname && @ssl_socket.respond_to?(:hostname=)
        @ssl_socket.hostname = hostname
      end
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

    def ssl_version
      @ssl_socket.ssl_version if @ssl_socket.respond_to?(:ssl_version)
    end

    def ssl_cipher
      @ssl_socket.cipher
    end

    def ssl_state
      @ssl_socket.state
    end

    def peer_cert
      @ssl_socket.peer_cert
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
      debug(str)
      str
    end

    def read(*args)
      str = @ssl_socket.read(*args)
      debug(str)
      str
    end

    def readpartial(*args)
      str = @ssl_socket.readpartial(*args)
      debug(str)
      str
    end

    def <<(str)
      rv = @ssl_socket.write(str)
      debug(str)
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

    def debug(str)
      @debug_dev << str if @debug_dev && str
    end
  end


  # Wraps up a Socket for method interception.
  module SocketWrap
    def initialize(socket, *args)
      super(*args)
      @socket = socket
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

    def readpartial(*args)
      # StringIO doesn't support :readpartial
      if @socket.respond_to?(:readpartial)
        @socket.readpartial(*args)
      else
        @socket.read(*args)
      end
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


  # Module for intercepting Socket methods and dumps in/out to given debugging
  # device.  debug_dev must respond to <<.
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

    def readpartial(*args)
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
      if str && @debug_dev
        if str.index("\0")
          require 'hexdump'
          str.force_encoding('BINARY') if str.respond_to?(:force_encoding)
          @debug_dev << HexDump.encode(str).join("\n")
        else
          @debug_dev << str
        end
      end
    end
  end


  # Dummy Socket for emulating loopback test.
  class LoopBackSocket
    include SocketWrap

    def initialize(host, port, response)
      super(response.is_a?(StringIO) ? response : StringIO.new(response))
      @host = host
      @port = port
    end

    def <<(str)
      # ignored
    end
  end


  # Manages a HTTP session with a Site.
  class Session
    include HTTPClient::Timeout
    include Util

    # Destination site
    attr_reader :dest
    # Proxy site
    attr_accessor :proxy
    # Boolean value for Socket#sync
    attr_accessor :socket_sync
    # Requested protocol version
    attr_accessor :requested_version
    # Device for dumping log for debugging
    attr_accessor :debug_dev

    attr_accessor :connect_timeout
    attr_accessor :connect_retry
    attr_accessor :send_timeout
    attr_accessor :receive_timeout
    attr_accessor :read_block_size
    attr_accessor :protocol_retry_count

    attr_accessor :socket_local

    attr_accessor :ssl_config
    attr_reader :ssl_peer_cert
    attr_accessor :test_loopback_http_response

    attr_accessor :transparent_gzip_decompression
    attr_reader :last_used

    def initialize(client, dest, agent_name, from)
      @client = client
      @dest = dest
      @proxy = nil
      @socket_sync = true
      @requested_version = nil

      @debug_dev = nil

      @connect_timeout = nil
      @connect_retry = 1
      @send_timeout = nil
      @receive_timeout = nil
      @read_block_size = nil
      @protocol_retry_count = 5

      @ssl_config = nil
      @ssl_peer_cert = nil

      @test_loopback_http_response = nil
      @socket_local = Site::EMPTY

      @agent_name = agent_name
      @from = from
      @state = :INIT

      @requests = []

      @status = nil
      @reason = nil
      @headers = []

      @socket = nil
      @readbuf = nil

      @transparent_gzip_decompression = false
      @last_used = nil
    end

    # Send a request to the server
    def query(req)
      connect if @state == :INIT
      # Use absolute URI (not absolute path) iif via proxy AND not HTTPS.
      req.header.request_absolute_uri = !@proxy.nil? && !https?(@dest)
      begin
        timeout(@send_timeout, SendTimeoutError) do
          set_header(req)
          req.dump(@socket)
          # flush the IO stream as IO::sync mode is false
          @socket.flush unless @socket_sync
        end
      rescue Errno::ECONNABORTED, Errno::ECONNRESET, Errno::EPIPE, IOError
        # JRuby can raise IOError instead of ECONNRESET for now
        close
        raise KeepAliveDisconnected.new(self, $!)
      rescue HTTPClient::TimeoutError
        close
        raise
      rescue => e
        close
        if SSLEnabled and e.is_a?(OpenSSL::SSL::SSLError)
          raise KeepAliveDisconnected.new(self, e)
        else
          raise
        end
      end

      @state = :META if @state == :WAIT
      @next_connection = nil
      @requests.push(req)
      @last_used = Time.now
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

    def get_header
      begin
        if @state != :META
          raise RuntimeError.new("get_status must be called at the beginning of a session")
        end
        read_header
      rescue
        close
        raise
      end
      [@version, @status, @reason, @headers]
    end

    def eof?
      if !@content_length.nil?
        @content_length == 0
      else
        @socket.closed? or @socket.eof?
      end
    end

    def get_body(&block)
      begin
        read_header if @state == :META
        return nil if @state != :DATA
        if @transparent_gzip_decompression
          block = content_inflater_block(@content_encoding, block)
        end
        if @chunked
          read_body_chunked(&block)
        elsif @content_length
          read_body_length(&block)
        else
          read_body_rest(&block)
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
      nil
    end

  private

    # This inflater allows deflate compression with/without zlib header
    class LenientInflater
      def initialize
        @inflater = Zlib::Inflate.new(Zlib::MAX_WBITS)
        @first = true
      end

      def inflate(body)
        if @first
          first_inflate(body)
        else
          @inflater.inflate(body)
        end
      end

    private

      def first_inflate(body)
        @first = false
        begin
          @inflater.inflate(body)
        rescue Zlib::DataError
          # fallback to deflate without zlib header
          @inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
          @inflater.inflate(body)
        end
      end
    end

    def content_inflater_block(content_encoding, block)
      case content_encoding
      when 'gzip', 'x-gzip'
        # zlib itself has a functionality to decompress gzip stream.
        # - zlib 1.2.5 Manual
        #   http://www.zlib.net/manual.html#Advanced
        # > windowBits can also be greater than 15 for optional gzip decoding. Add 32 to
        # > windowBits to enable zlib and gzip decoding with automatic header detection,
        # > or add 16 to decode only the gzip format
        inflate_stream = Zlib::Inflate.new(Zlib::MAX_WBITS + 32)
      when 'deflate'
        inflate_stream = LenientInflater.new
      else
        return block
      end
      Proc.new { |buf|
        block.call(inflate_stream.inflate(buf))
      }
    end

    def set_header(req)
      if @requested_version
        if /^(?:HTTP\/|)(\d+.\d+)$/ =~ @requested_version
          req.http_version = $1
        end
      end
      if @agent_name && req.header.get('User-Agent').empty?
        req.header.set('User-Agent', "#{@agent_name} #{LIB_NAME}")
      end
      if @from && req.header.get('From').empty?
        req.header.set('From', @from)
      end
      if req.header.get('Accept').empty?
        req.header.set('Accept', '*/*')
      end
      if @transparent_gzip_decompression
        req.header.set('Accept-Encoding', 'gzip,deflate')
      end
      if req.header.get('Date').empty?
        req.header.set_date_header
      end
    end

    # Connect to the server
    def connect
      site = @proxy || @dest
      retry_number = 0
      begin
        timeout(@connect_timeout, ConnectTimeoutError) do
          @socket = create_socket(site)
          if https?(@dest)
            if @socket.is_a?(LoopBackSocket)
              connect_ssl_proxy(@socket, urify(@dest.to_s)) if @proxy
            else
              @socket = create_ssl_socket(@socket)
              connect_ssl_proxy(@socket, urify(@dest.to_s)) if @proxy
              begin
                @socket.ssl_connect(@dest.host)
              ensure
                if $DEBUG
                  warn("Protocol version: #{@socket.ssl_version}")
                  warn("Cipher: #{@socket.ssl_cipher.inspect}")
                  warn("State: #{@socket.ssl_state}")
                end
              end
              @socket.post_connection_check(@dest)
              @ssl_peer_cert = @socket.peer_cert
            end
          end
          # Use Ruby internal buffering instead of passing data immediately
          # to the underlying layer
          # => we need to to call explicitly flush on the socket
          @socket.sync = @socket_sync
        end
      rescue RetryableResponse
        retry_number += 1
        if retry_number < @protocol_retry_count
          retry
        end
        raise BadResponseError.new("connect to the server failed with status #{@status} #{@reason}")
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
    end

    def create_socket(site)
      socket = nil
      begin
        @debug_dev << "! CONNECT TO #{site.host}:#{site.port}\n" if @debug_dev
        clean_host = site.host.delete("[]")
        if str = @test_loopback_http_response.shift
          socket = LoopBackSocket.new(clean_host, site.port, str)
        elsif @socket_local == Site::EMPTY
          socket = TCPSocket.new(clean_host, site.port)
        else
          clean_local = @socket_local.host.delete("[]")
          socket = TCPSocket.new(clean_host, site.port, clean_local, @socket_local.port)
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
      SSLSocketWrap.new(raw_socket, @ssl_config, @debug_dev)
    end

    def connect_ssl_proxy(socket, uri)
      req = HTTP::Message.new_connect_request(uri)
      @client.request_filter.each do |filter|
        filter.filter_request(req)
      end
      set_header(req)
      req.dump(@socket)
      @socket.flush unless @socket_sync
      res = HTTP::Message.new_response('')
      parse_header
      res.http_version, res.status, res.reason = @version, @status, @reason
      @headers.each do |key, value|
        res.header.set(key.to_s, value)
      end
      commands = @client.request_filter.collect { |filter|
        filter.filter_response(req, res)
      }
      if commands.find { |command| command == :retry }
        raise RetryableResponse.new(res)
      end
      unless @status == 200
        raise BadResponseError.new("connect to ssl proxy failed with status #{@status} #{@reason}", res)
      end
    end

    # Read status block.
    def read_header
      @content_length = nil
      @chunked = false
      @content_encoding = nil
      @chunk_length = 0
      parse_header
      # Header of the request has been parsed.
      @state = :DATA
      req = @requests.shift
      if req.header.request_method == 'HEAD' or no_message_body?(@status)
        @content_length = 0
        if @next_connection
          @state = :WAIT
        else
          close
        end
      end
      @next_connection = false if !@content_length and !@chunked
    end

    StatusParseRegexp = %r(\AHTTP/(\d+\.\d+)\s+(\d\d\d)\s*([^\r\n]+)?\r?\n\z)
    def parse_header
     t = Thread.new {
        initial_line = nil
        begin
          begin
            initial_line = @socket.gets("\n")
            if initial_line.nil?
              close
              raise KeepAliveDisconnected.new(self)
            end
          rescue Errno::ECONNABORTED, Errno::ECONNRESET, Errno::EPIPE, IOError
            # JRuby can raise IOError instead of ECONNRESET for now
            close
            raise KeepAliveDisconnected.new(self, $!)
          end
          if StatusParseRegexp !~ initial_line
            @version = '0.9'
            @status = nil
            @reason = nil
            @next_connection = false
            @content_length = nil
            @readbuf = initial_line
            break
          end
          @version, @status, @reason = $1, $2.to_i, $3
          @next_connection = HTTP::Message.keep_alive_enabled?(@version)
          @headers = []
          while true
            line = @socket.gets("\n")
            unless line
              raise BadResponseError.new('unexpected EOF')
            end
            line.chomp!
            break if line.empty?
            if line[0] == ?\  or line[0] == ?\t
              last = @headers.last[1]
              last << ' ' unless last.empty?
              last << line.strip
            else
              key, value = line.strip.split(/\s*:\s*/, 2)
              parse_content_header(key, value)
              @headers << [key, value]
            end
          end
        end while (@version == '1.1' && @status == 100)

     }
     t.abort_on_exception = true
     success = t.join(@receive_timeout)
     raise ReceiveTimeoutError if success.nil?

    end

    def no_message_body?(status)
      !status.nil? && # HTTP/0.9
        ((status >= 100 && status < 200) || status == 204 || status == 304)
    end

    def parse_content_header(key, value)
      key = key.downcase
      case key
      when 'content-length'
        @content_length = value.to_i
      when 'content-encoding'
        @content_encoding = value.downcase
      when 'transfer-encoding'
        if value.downcase == 'chunked'
          @chunked = true
          @chunk_length = 0
          @content_length = nil
        end
      when 'connection', 'proxy-connection'
        if value.downcase == 'keep-alive'
          @next_connection = true
        else
          @next_connection = false
        end
      end
    end

    def read_body_length(&block)
      return nil if @content_length == 0
      while true
        buf = empty_bin_str
        maxbytes = @read_block_size
        maxbytes = @content_length if maxbytes > @content_length && @content_length > 0
        timeout(@receive_timeout, ReceiveTimeoutError) do
          begin
            @socket.readpartial(maxbytes, buf)
          rescue EOFError
            close
            buf = nil
          end
        end
        if buf && buf.bytesize > 0
          @content_length -= buf.bytesize
          yield buf
        else
          @content_length = 0
        end
        return if @content_length == 0
      end
    end

    RS = "\r\n"
    def read_body_chunked(&block)
      buf = empty_bin_str
      while true
        len = @socket.gets(RS)
        if len.nil? # EOF
          close
          return
        end
        @chunk_length = len.hex
        if @chunk_length == 0
          @content_length = 0
          @socket.gets(RS)
          return
        end
        timeout(@receive_timeout, ReceiveTimeoutError) do
          @socket.read(@chunk_length, buf)
          @socket.read(2)
        end
        unless buf.empty?
          yield buf
        end
      end
    end

    def read_body_rest
      if @readbuf and @readbuf.bytesize > 0
        yield @readbuf
        @readbuf = nil
      end
      while true
        buf = empty_bin_str
        timeout(@receive_timeout, ReceiveTimeoutError) do
          begin
            @socket.readpartial(@read_block_size, buf)
          rescue EOFError
            buf = nil
          end
        end
        if buf && buf.bytesize > 0
          yield buf
        else
          return
        end
      end
    end

    def empty_bin_str
      str = ''
      str.force_encoding('BINARY') if str.respond_to?(:force_encoding)
      str
    end
  end


end
