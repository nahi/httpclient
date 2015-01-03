# HTTPClient - HTTP client library.
# Copyright (C) 2000-2015  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.
#
# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


require 'httpclient/ssl_config'


class HTTPClient

if defined?(JRuby)

require 'java'

  class SSLSocket
    java_import 'javax.net.ssl.SSLSocketFactory'
    java_import 'java.io.BufferedInputStream'

    def self.create_socket(session)
      # TODO proxy
      new(session.dest, session.ssl_config, session.debug_dev)
    end

    def initialize(dest, context, debug_dev = nil)
      # TODO context: the hard part...
      @debug_dev = debug_dev
      factory = SSLSocketFactory.getDefault
      begin
        @ssl_socket = factory.createSocket(dest.host, dest.port)
        @ssl_socket.startHandshake
        @outstr = @ssl_socket.getOutputStream
        @instr = BufferedInputStream.new(@ssl_socket.getInputStream)
        @buf = (' ' * (1024 * 16)).to_java_bytes
        @bufstr = ''
      rescue java.security.GeneralSecurityException => e
        raise OpenSSL::SSL::SSLError.new(e.getMessage)
      rescue javax.net.ssl.SSLException => e
        raise OpenSSL::SSL::SSLError.new(e.getMessage)
      end
    end

    def peer_cert
      # TODO
    end

    def close
      @ssl_socket.close
    end

    def closed?
      @ssl_socket.isClosed
    end

    def eof?
      @ssl_socket.isClosed
    end

    def gets(rs)
      while (size = @bufstr.index(rs)).nil?
        if fill() == -1
          size = @bufstr.size
          break
        end
      end
      str = @bufstr.slice!(0, size + rs.size)
      debug(str)
      str
    end

    def read(size, buf = nil)
      while @bufstr.size < size
        if fill() == -1
          break
        end
      end
      str = @bufstr.slice!(0, size)
      debug(str)
      if buf
        buf.replace(str)
      else
        str
      end
    end

    def readpartial(size, buf = nil)
      while @bufstr.size == 0
        if fill() == -1
          raise EOFError.new('end of file reached')
        end
      end
      str = @bufstr.slice!(0, size)
      debug(str)
      if buf
        buf.replace(str)
      else
        str
      end
    end

    def <<(str)
      rv = @outstr.write(str.to_java_bytes)
      debug(str)
      rv
    end

    def flush
      @ssl_socket.flush
    end

    def sync
      true
    end

    def sync=(sync)
      unless sync
        raise "sync = false is not supported"
      end
    end

  private

    def fill
      size = @instr.read(@buf)
      if size > 0
        @bufstr << String.from_java_bytes(@buf, Encoding::BINARY)[0, size]
      end
      size
    end

    def debug(str)
      @debug_dev << str if @debug_dev && str
    end
  end

else

  # Wraps up OpenSSL::SSL::SSLSocket and offers debugging features.
  class SSLSocket
    def self.create_socket(session)
      site = session.proxy || session.dest
      socket = session.create_socket(site.host, site.port)
      begin
        if session.proxy
          session.connect_ssl_proxy(socket, Util.urify(session.dest.to_s))
        end
        ssl_socket = new(socket, session.ssl_config, session.debug_dev)
        ssl_socket.ssl_connect(session.dest.host)
        ssl_socket
      rescue
        socket.close
        raise
      end
    end

    def initialize(socket, context, debug_dev = nil)
      unless SSLEnabled
        raise ConfigurationError.new('Ruby/OpenSSL module is required')
      end
      @socket = socket
      @context = context
      @ssl_socket = create_openssl_socket(@socket)
      @debug_dev = debug_dev
    end

    def ssl_connect(hostname = nil)
      if hostname && @ssl_socket.respond_to?(:hostname=)
        @ssl_socket.hostname = hostname
      end
      @ssl_socket.connect
      if $DEBUG
        if @ssl_socket.respond_to?(:ssl_version)
          warn("Protocol version: #{@ssl_socket.ssl_version}")
        end
        warn("Cipher: #{@ssl_socket.cipher.inspect}")
        warn("State: #{@ssl_socket.state}")
      end
      post_connection_check(hostname)
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

    def gets(rs)
      str = @ssl_socket.gets(rs)
      debug(str)
      str
    end

    def read(size, buf = nil)
      str = @ssl_socket.read(size, buf)
      debug(str)
      str
    end

    def readpartial(size, buf = nil)
      str = @ssl_socket.readpartial(size, buf)
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

    def post_connection_check(hostname)
      verify_mode = @context.verify_mode || OpenSSL::SSL::VERIFY_NONE
      if verify_mode == OpenSSL::SSL::VERIFY_NONE
        return
      elsif @ssl_socket.peer_cert.nil? and
        check_mask(verify_mode, OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT)
        raise OpenSSL::SSL::SSLError.new('no peer cert')
      end
      if @ssl_socket.respond_to?(:post_connection_check) and RUBY_VERSION > "1.8.4"
        @ssl_socket.post_connection_check(hostname)
      else
        @context.post_connection_check(@ssl_socket.peer_cert, hostname)
      end
    end

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

end

end
