# HTTPClient - HTTP client library.
# Copyright (C) 2000-2008  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.
#
# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


class HTTPClient

  begin
    require 'openssl'
    SSLEnabled = true
  rescue LoadError
    SSLEnabled = false
  end

  # HTTPClient::SSLConfig -- SSL configuration of a client.
  #
  class SSLConfig
    include OpenSSL if SSLEnabled

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
      @cert_store = X509::Store.new
      @client_cert = @client_key = @client_ca = nil
      @verify_mode = SSL::VERIFY_PEER | SSL::VERIFY_FAIL_IF_NO_PEER_CERT
      @verify_depth = nil
      @verify_callback = nil
      @dest = nil
      @timeout = nil
      @options = defined?(SSL::OP_ALL) ? SSL::OP_ALL | SSL::OP_NO_SSLv2 : nil
      @ciphers = "ALL:!ADH:!LOW:!EXP:!MD5:+SSLv2:@STRENGTH"
      load_cacerts
    end

    def set_client_cert_file(cert_file, key_file)
      @client_cert = X509::Certificate.new(File.open(cert_file).read)
      @client_key = PKey::RSA.new(File.open(key_file).read)
      change_notify
    end

    def clear_cert_store
      @cert_store = X509::Store.new
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
      crl = X509::CRL.new(File.open(crl_file).read)
      @cert_store.add_crl(crl)
      @cert_store.flags = X509::V_FLAG_CRL_CHECK | X509::V_FLAG_CRL_CHECK_ALL
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
      raise SSL::SSLError, "hostname was not match with the server certificate"
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

    def load_cacerts
      file = File.join(File.dirname(__FILE__), 'cacert.p7s')
      if File.exist?(file)
        require 'openssl'
        dist_cert =<<__DIST_CERT__
-----BEGIN CERTIFICATE-----
MIIC/jCCAmegAwIBAgIBATANBgkqhkiG9w0BAQUFADBNMQswCQYDVQQGEwJKUDER
MA8GA1UECgwIY3Rvci5vcmcxFDASBgNVBAsMC0RldmVsb3BtZW50MRUwEwYDVQQD
DAxodHRwLWFjY2VzczIwHhcNMDcwOTExMTM1ODMxWhcNMDkwOTEwMTM1ODMxWjBN
MQswCQYDVQQGEwJKUDERMA8GA1UECgwIY3Rvci5vcmcxFDASBgNVBAsMC0RldmVs
b3BtZW50MRUwEwYDVQQDDAxodHRwLWFjY2VzczIwgZ8wDQYJKoZIhvcNAQEBBQAD
gY0AMIGJAoGBALi66ujWtUCQm5HpMSyr/AAIFYVXC/dmn7C8TR/HMiUuW3waY4uX
LFqCDAGOX4gf177pX+b99t3mpaiAjJuqc858D9xEECzhDWgXdLbhRqWhUOble4RY
c1yWYC990IgXJDMKx7VAuZ3cBhdBxtlE9sb1ZCzmHQsvTy/OoRzcJCrTAgMBAAGj
ge0wgeowDwYDVR0TAQH/BAUwAwEB/zAxBglghkgBhvhCAQ0EJBYiUnVieS9PcGVu
U1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUJNE0GGaRKmN2qhnO
FyBWVl4Qj6owDgYDVR0PAQH/BAQDAgEGMHUGA1UdIwRuMGyAFCTRNBhmkSpjdqoZ
zhcgVlZeEI+qoVGkTzBNMQswCQYDVQQGEwJKUDERMA8GA1UECgwIY3Rvci5vcmcx
FDASBgNVBAsMC0RldmVsb3BtZW50MRUwEwYDVQQDDAxodHRwLWFjY2VzczKCAQEw
DQYJKoZIhvcNAQEFBQADgYEAH11tstSUuqFpMqoh/vM5l3Nqb8ygblbqEYQs/iG/
UeQkOZk/P1TxB6Ozn2htJ1srqDpUsncFVZ/ecP19GkeOZ6BmIhppcHhE5WyLBcPX
It5q1BW0PiAzT9LlEGoaiW0nw39so0Pr1whJDfc1t4fjdk+kSiMIzRHbTDvHWfpV
nTA=
-----END CERTIFICATE-----
__DIST_CERT__
        p7 = PKCS7.read_smime(File.open(file) { |f| f.read })
        selfcert = X509::Certificate.new(dist_cert)
        store = X509::Store.new
        store.add_cert(selfcert)
        if (p7.verify(nil, store, p7.data, 0))
          set_trust_ca(file)
        else
          STDERR.puts("cacerts: #{file} loading failed")
        end
      end
    end
  end


end
