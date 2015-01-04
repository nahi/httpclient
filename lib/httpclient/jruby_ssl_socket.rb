# HTTPClient - HTTP client library.
# Copyright (C) 2000-2015  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.
#
# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


require 'java'
require 'httpclient/ssl_config'


class HTTPClient

unless defined?(SSLSocket)

  class JRubySSLSocket
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

  SSLSocket = JRubySSLSocket

end

end
