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
    java_import 'java.io.BufferedInputStream'
    java_import 'java.io.ByteArrayInputStream'
    java_import 'java.io.InputStreamReader'
    java_import 'java.security.KeyStore'
    java_import 'javax.net.ssl.KeyManagerFactory'
    java_import 'javax.net.ssl.SSLContext'
    java_import 'javax.net.ssl.SSLSocketFactory'
    java_import 'javax.net.ssl.TrustManager'
    java_import 'javax.net.ssl.TrustManagerFactory'
    java_import 'javax.net.ssl.X509TrustManager'
    java_import 'org.jruby.ext.openssl.x509store.PEMInputOutput'
    java_import 'org.jruby.ext.openssl.x509store.X509AuxCertificate'

    class JavaCertificate
      def initialize(cert)
        @cert = cert
      end

      def subject
        @cert.getSubjectDN
      end

      def to_text
        @cert.toString
      end

      def to_pem
        '(not in PEM format)'
      end
    end

    class SSLStoreContext
      attr_reader :current_cert, :chain, :error_depth, :error, :error_string

      def initialize(current_cert, chain, error_depth, error, error_string)
        @current_cert, @chain, @error_depth, @error, @error_string =
          current_cert, chain, error_depth, error, error_string
      end
    end

    class JSSEVerifyCallback
      def initialize(verify_callback)
        @verify_callback = verify_callback
      end

      def call(is_ok, chain, error_depth = -1, error = -1, error_string = '(unknown)')
        if @verify_callback
          ruby_chain = chain.map { |cert|
            JavaCertificate.new(cert)
          }.reverse
          # NOTE: The order depends on provider implementation
          ruby_chain.each do |cert|
            is_ok = @verify_callback.call(
              is_ok,
              SSLStoreContext.new(cert, ruby_chain, error_depth, error, error_string)
            )
          end
        end
        is_ok
      end
    end

    class VerifyNoneTrustManagerFactory
      class VerifyNoneTrustManager
        include X509TrustManager

        def initialize(verify_callback)
          @verify_callback = JSSEVerifyCallback.new(verify_callback)
        end

        def checkServerTrusted(chain, authType)
          @verify_callback.call(true, chain)
        end

        def checkClientTrusted(chain, authType); end
        def getAcceptedIssuers; end
      end

      def initialize(verify_callback = nil)
        @verify_callback = verify_callback
      end

      def init(trustStore)
        @managers = [VerifyNoneTrustManager.new(@verify_callback)].to_java(X509TrustManager)
      end

      def getTrustManagers
        @managers
      end
    end

    class SystemTrustManagerFactory
      class SystemTrustManager
        include X509TrustManager

        def initialize(original, verify_callback)
          @original = original
          @verify_callback = JSSEVerifyCallback.new(verify_callback)
        end

        def checkServerTrusted(chain, authType)
          is_ok = false
          excn = nil
          # TODO can we detect the depth from excn?
          error_depth = -1
          error = nil
          error_message = nil
          begin
            @original.checkServerTrusted(chain, authType)
            is_ok = true
          rescue java.security.cert.CertificateException => excn
            is_ok = false
            error = excn.class.name
            error_message = excn.getMessage
          end
          is_ok = @verify_callback.call(is_ok, chain, error_depth, error, error_message)
          unless is_ok
            excn ||= RuntimeError.new('verifycallback failed')
            raise excn
          end
        end

        def checkClientTrusted(chain, authType); end
        def getAcceptedIssuers; end
      end

      def initialize(verify_callback = nil)
        @verify_callback = verify_callback
      end

      def init(trust_store)
        tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
        tmf.java_method(:init, [KeyStore]).call(trust_store)
        @original = tmf.getTrustManagers.find { |tm|
          tm.is_a?(X509TrustManager)
        }
        @managers = [SystemTrustManager.new(@original, @verify_callback)].to_java(X509TrustManager)
      end

      def getTrustManagers
        @managers
      end
    end

    module PEMUtils
      def self.read(pem, password)
        if password
          password = password.unpack('C*').to_java(:char)
        end
        PEMInputOutput.readPEM(InputStreamReader.new(ByteArrayInputStream.new(pem.to_java_bytes)), password)
      end

      def self.read_private_key(pem, password)
        if password
          password = password.unpack('C*').to_java(:char)
        end
        PEMInputOutput.read_private_key(InputStreamReader.new(ByteArrayInputStream.new(pem.to_java_bytes)), password)
      end
    end

    class KeyStoreLoader
      PASSWORD = 'secret'.unpack('C*').to_java(:char)

      def initialize
        @keystore = KeyStore.getInstance('JKS')
        @keystore.load(nil)
      end

      def add(cert_file, key_file)
        cert_str = cert_file.respond_to?(:to_pem) ? cert_file.to_pem : File.read(cert_file.to_s)
        cert = PEMUtils.read(cert_str, nil)
        @keystore.setCertificateEntry('client_cert', cert)
        key_str = key_file.respond_to?(:to_pem) ? key_file.to_pem : File.read(key_file.to_s)
        key_pair = PEMUtils.read_private_key(key_str, nil)
        @keystore.setKeyEntry('client_key', key_pair.getPrivate, PASSWORD, [cert].to_java(X509AuxCertificate))
      end

      def keystore
        @keystore
      end
    end

    class TrustStoreLoader
      attr_reader :size

      def initialize
        @trust_store = KeyStore.getInstance('JKS')
        @trust_store.load(nil)
        @size = 0
      end

      def add(file_or_dir)
        return if file_or_dir == :default
        if File.directory?(file_or_dir)
          warn('directory not yet supported')
        else
          pem = nil
          File.read(file_or_dir).each_line do |line|
            case line
            when /-----BEGIN CERTIFICATE-----/
              pem = ''
            when /-----END CERTIFICATE-----/
              cert = PEMUtils.read(pem, nil)
              @size += 1
              @trust_store.setCertificateEntry("cert_#{@size}", cert)
            else
              if pem
                pem << line
              end
            end
          end
        end
      end

      def trust_store
        if @size == 0
          nil
        else
          @trust_store
        end
      end
    end

    def self.create_socket(session)
      # TODO proxy
      # TODO post_connection_check
      # TODO client_cert/client_key -> keyStore(key, cert)

      # TODO OpenSSL specific options are ignored;
      # ssl_config.verify_depth
      # ssl_config.options
      # ssl_config.ciphers
      # ssl_config.client_ca

      # TODO revocation is performed by -Dcom.sun.security.enableCRLDP=true -Dcom.sun.net.ssl.checkRevocation=true
      # example: https://test-sspev.verisign.com:2443/test-SSPEV-revoked-verisign.html
      new(session.dest, session.ssl_config, session.debug_dev)
    end

    def initialize(dest, config, debug_dev = nil)
      @debug_dev = debug_dev

      if config.ssl_version == :auto
        ssl_version = 'TLS'
      else
        ssl_version = config.to_s.gsub(/_/, '.')
      end
      unless config.cert_store_crl_items.empty?
        raise NotImplementedError.new('Manual CRL configuration is not yet supported')
      end

      km = nil
      if config.client_cert && config.client_key
        loader = KeyStoreLoader.new
        loader.add(config.client_cert, config.client_key)
        kmf = KeyManagerFactory.getInstance('SunX509')
        kmf.init(loader.keystore, KeyStoreLoader::PASSWORD)
        km = kmf.getKeyManagers
      end

      trust_store = nil
      verify_callback = config.verify_callback || config.method(:default_verify_callback)
      if config.verify_mode == nil
        tmf = VerifyNoneTrustManagerFactory.new(verify_callback)
      else
        tmf = SystemTrustManagerFactory.new(verify_callback)
        loader = TrustStoreLoader.new
        config.cert_store_items.each do |item|
          loader.add(item)
        end
        trust_store = loader.trust_store
        p loader.size
      end
      tmf.init(trust_store)
      tm = tmf.getTrustManagers

      ctx = SSLContext.getInstance(ssl_version)
      ctx.init(km, tm, nil)
      if config.timeout
        ctx.getClientSessionContext.setSessionTimeout(config.timeout)
      end

      factory = ctx.getSocketFactory
      begin
        @ssl_socket = factory.createSocket(dest.host, dest.port)
        @ssl_socket.startHandshake
        @peer_cert = JavaCertificate.new(@ssl_socket.getSession.getPeerCertificateChain.first)
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
      @peer_cert
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
