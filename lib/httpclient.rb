# HTTPClient - HTTP client library.
# Copyright (C) 2000-2008  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.

# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.

# httpclient.rb is based on http-access.rb in http-access/0.0.4.  Some part
# of code in http-access.rb was recycled in httpclient.rb.  Those part is
# copyrighted by Maehashi-san.


# Ruby standard library
require 'timeout'
require 'uri'
require 'socket'
require 'thread'
require 'stringio'
require 'digest/md5'

# Extra library
require 'httpclient/http'
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

  VERSION = '2.1.2'
  RUBY_VERSION_STRING = "ruby #{RUBY_VERSION} (#{RUBY_RELEASE_DATE}) [#{RUBY_PLATFORM}]"
  s = %w$Id$
  RCS_FILE, RCS_REVISION = s[1][/.*(?=,v$)/], s[2]

  SSLEnabled = begin
      require 'openssl'
      true
    rescue LoadError
      false
    end

  NTLMEnabled = begin
      require 'net/ntlm'
      true
    rescue LoadError
      false
    end

  SSPIEnabled = begin
      require 'win32/sspi'
      true
    rescue LoadError
      false
    end

  DEBUG_SSL = true


module Util
  def urify(uri)
    if uri.nil?
      nil
    elsif uri.is_a?(URI)
      uri
    else
      URI.parse(uri.to_s)
    end
  end

  def uri_part_of(uri, part)
    ((uri.scheme == part.scheme) and
      (uri.host == part.host) and
      (uri.port == part.port) and
      uri.path.upcase.index(part.path.upcase) == 0)
  end
  module_function :uri_part_of

  def uri_dirname(uri)
    uri = uri.clone
    uri.path = uri.path.sub(/\/[^\/]*\z/, '/')
    uri
  end
  module_function :uri_dirname

  def hash_find_value(hash)
    hash.each do |k, v|
      return v if yield(k, v)
    end
    nil
  end
  module_function :hash_find_value

  def parse_challenge_param(param_str)
    param = {}
    param_str.scan(/\s*([^\,]+(?:\\.[^\,]*)*)/).each do |str|
      key, value = str[0].scan(/\A([^=]+)=(.*)\z/)[0]
      if /\A"(.*)"\z/ =~ value
        value = $1.gsub(/\\(.)/, '\1')
      end
      param[key] = value
    end
    param
  end
  module_function :parse_challenge_param
end



# HTTPClient::SSLConfig -- SSL configuration of a client.
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
    @ciphers = "ALL:!ADH:!LOW:!EXP:!MD5:+SSLv2:@STRENGTH"
    load_cacerts
  end

  def set_client_cert_file(cert_file, key_file)
    @client_cert = OpenSSL::X509::Certificate.new(File.open(cert_file).read)
    @client_key = OpenSSL::PKey::RSA.new(File.open(key_file).read)
    change_notify
  end

  def clear_cert_store
    @cert_store = OpenSSL::X509::Store.new
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
    raise OpenSSL::SSL::SSLError, "hostname was not match with the server certificate"
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
    file = File.join(File.dirname(__FILE__), 'httpclient', 'cacert.p7s')
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
      p7 = OpenSSL::PKCS7.read_smime(File.open(file) { |f| f.read })
      selfcert = OpenSSL::X509::Certificate.new(dist_cert)
      store = OpenSSL::X509::Store.new
      store.add_cert(selfcert)
      if (p7.verify(nil, store, p7.data, 0))
        set_trust_ca(file)
      else
        STDERR.puts("cacerts: #{file} loading failed")
      end
    end
  end
end


# HTTPClient::BasicAuth -- BasicAuth repository.
#
class BasicAuth # :nodoc:
  attr_reader :scheme

  def initialize
    @cred = nil
    @auth = {}
    @challengeable = {}
    @scheme = "Basic"
  end

  def reset_challenge
    @challengeable.clear
  end

  # uri == nil for generic purpose
  def set(uri, user, passwd)
    if uri.nil?
      @cred = ["#{user}:#{passwd}"].pack('m').tr("\n", '')
    else
      uri = Util.uri_dirname(uri)
      @auth[uri] = ["#{user}:#{passwd}"].pack('m').tr("\n", '')
    end
  end

  # send cred only when a given uri is;
  #   - child page of challengeable(got WWW-Authenticate before) uri and,
  #   - child page of defined credential
  def get(req)
    target_uri = req.header.request_uri
    return nil unless @challengeable.find { |uri, ok|
      Util.uri_part_of(target_uri, uri) and ok
    }
    return @cred if @cred
    Util.hash_find_value(@auth) { |uri, cred|
      Util.uri_part_of(target_uri, uri)
    }
  end

  def challenge(uri, param_str)
    @challengeable[uri] = true
    true
  end
end


# HTTPClient::DigestAuth 
#
class DigestAuth # :nodoc:
  attr_reader :scheme

  def initialize
    @auth = {}
    @challenge = {}
    @nonce_count = 0
    @scheme = "Digest"
  end

  def reset_challenge
    @challenge.clear
  end

  def set(uri, user, passwd)
    if uri
      uri = Util.uri_dirname(uri)
      @auth[uri] = [user, passwd]
    end
  end

  # send cred only when a given uri is;
  #   - child page of challengeable(got WWW-Authenticate before) uri and,
  #   - child page of defined credential
  def get(req)
    target_uri = req.header.request_uri
    param = Util.hash_find_value(@challenge) { |uri, v|
      Util.uri_part_of(target_uri, uri)
    }
    return nil unless param
    user, passwd = Util.hash_find_value(@auth) { |uri, auth_data|
      Util.uri_part_of(target_uri, uri)
    }
    return nil unless user
    uri = req.header.request_uri
    calc_cred(req.header.request_method, uri, user, passwd, param)
  end

  def challenge(uri, param_str)
    @challenge[uri] = Util.parse_challenge_param(param_str)
    true
  end

private

  # this method is implemented by sromano and posted to
  # http://tools.assembla.com/breakout/wiki/DigestForSoap
  # Thanks!
  # supported algorithm: MD5 only for now
  def calc_cred(method, uri, user, passwd, param)
    a_1 = "#{user}:#{param['realm']}:#{passwd}"
    a_2 = "#{method}:#{uri.path}"
    @nonce_count += 1
    message_digest = []
    message_digest << Digest::MD5.hexdigest(a_1)
    message_digest << param['nonce']
    message_digest << ('%08x' % @nonce_count)
    message_digest << param['nonce']
    message_digest << param['qop']
    message_digest << Digest::MD5.hexdigest(a_2)
    header = []
    header << "username=\"#{user}\""
    header << "realm=\"#{param['realm']}\""
    header << "nonce=\"#{param['nonce']}\""
    header << "uri=\"#{uri.path}\""
    header << "cnonce=\"#{param['nonce']}\""
    header << "nc=#{'%08x' % @nonce_count}"
    header << "qop=\"#{param['qop']}\""
    header << "response=\"#{Digest::MD5.hexdigest(message_digest.join(":"))}\""
    header << "algorithm=\"MD5\""
    header << "opaque=\"#{param['opaque']}\"" if param.key?('opaque')
    header.join(", ")
  end
end


# HTTPClient::NegotiateAuth 
#
class NegotiateAuth # :nodoc:
  attr_reader :scheme
  attr_reader :ntlm_opt

  def initialize
    @auth = {}
    @auth_default = nil
    @challenge = {}
    @scheme = "Negotiate"
    @ntlm_opt = {
      :ntlmv2 => true
    }
  end

  def reset_challenge
    @challenge.clear
  end

  def set(uri, user, passwd)
    if uri
      uri = Util.uri_dirname(uri)
      @auth[uri] = [user, passwd]
    else
      @auth_default = [user, passwd]
    end
  end

  def get(req)
    return nil unless NTLMEnabled
    target_uri = req.header.request_uri
    domain_uri, param = @challenge.find { |uri, v|
      Util.uri_part_of(target_uri, uri)
    }
    return nil unless param
    user, passwd = Util.hash_find_value(@auth) { |uri, auth_data|
      Util.uri_part_of(target_uri, uri)
    }
    unless user
      user, passwd = @auth_default
    end
    return nil unless user
    state = param[:state]
    authphrase = param[:authphrase]
    case state
    when :init
      t1 = Net::NTLM::Message::Type1.new
      return t1.encode64
    when :response
      t2 = Net::NTLM::Message.decode64(authphrase)
      t3 = t2.response({:user => user, :password => passwd}, @ntlm_opt.dup)
      @challenge.delete(domain_uri)
      return t3.encode64
    end
    nil
  end

  def challenge(uri, param_str)
    return false unless NTLMEnabled
    if param_str.nil? or @challenge[uri].nil?
      c = @challenge[uri] = {}
      c[:state] = :init
      c[:authphrase] = ""
    else
      c = @challenge[uri]
      c[:state] = :response
      c[:authphrase] = param_str
    end
    true
  end
end


# HTTPClient::SSPINegotiateAuth 
#
class SSPINegotiateAuth # :nodoc:
  attr_reader :scheme

  def initialize
    @challenge = {}
    @scheme = "Negotiate"
  end

  def reset_challenge
    @challenge.clear
  end

  def set(uri, user, passwd)
    # not supported
  end

  def get(req)
    return nil unless SSPIEnabled
    target_uri = req.header.request_uri
    domain_uri, param = @challenge.find { |uri, v|
      Util.uri_part_of(target_uri, uri)
    }
    return nil unless param
    state = param[:state]
    authenticator = param[:authenticator]
    authphrase = param[:authphrase]
    case state
    when :init
      authenticator = param[:authenticator] = Win32::SSPI::NegotiateAuth.new
      return authenticator.get_initial_token
    when :response
      @challenge.delete(domain_uri)
      return authenticator.complete_authentication(authphrase)
    end
    nil
  end

  def challenge(uri, param_str)
    return false unless SSPIEnabled
    if param_str.nil? or @challenge[uri].nil?
      c = @challenge[uri] = {}
      c[:state] = :init
      c[:authenticator] = nil
      c[:authphrase] = ""
    else
      c = @challenge[uri]
      c[:state] = :response
      c[:authphrase] = param_str
    end
    true
  end
end


class AuthFilterBase # :nodoc:
private

  def parse_authentication_header(res, tag)
    challenge = res.header[tag]
    unless challenge
      raise RuntimeError.new("no #{tag} header exists: #{res}")
    end
    challenge.collect { |c| parse_challenge_header(c) }
  end

  def parse_challenge_header(challenge)
    scheme, param_str = challenge.scan(/\A(\S+)(?:\s+(.*))?\z/)[0]
    if scheme.nil?
      raise RuntimeError.new("unsupported challenge: #{challenge}")
    end
    return scheme, param_str
  end
end


class WWWAuth < AuthFilterBase # :nodoc:
  attr_reader :basic_auth
  attr_reader :digest_auth
  attr_reader :negotiate_auth

  def initialize
    @basic_auth = BasicAuth.new
    @digest_auth = DigestAuth.new
    @negotiate_auth = NegotiateAuth.new
    # sort authenticators by priority
    @authenticator = [@negotiate_auth, @digest_auth, @basic_auth]
  end

  def reset_challenge
    @authenticator.each do |auth|
      auth.reset_challenge
    end
  end

  def set_auth(uri, user, passwd)
    @authenticator.each do |auth|
      auth.set(uri, user, passwd)
    end
    reset_challenge
  end

  def filter_request(req)
    @authenticator.each do |auth|
      if cred = auth.get(req)
        req.header.set('Authorization', auth.scheme + " " + cred)
        return
      end
    end
  end

  def filter_response(req, res)
    command = nil
    uri = req.header.request_uri
    if res.status == HTTP::Status::UNAUTHORIZED
      if challenge = parse_authentication_header(res, 'www-authenticate')
        challenge.each do |scheme, param_str|
          @authenticator.each do |auth|
            if scheme.downcase == auth.scheme.downcase
              challengeable = auth.challenge(uri, param_str)
              command = :retry if challengeable
            end
          end
        end
        # ignore unknown authentication scheme
      end
    end
    command
  end
end


class ProxyAuth < AuthFilterBase # :nodoc:
  attr_reader :basic_auth
  attr_reader :negotiate_auth
  attr_reader :sspi_negotiate_auth

  def initialize
    @basic_auth = BasicAuth.new
    @negotiate_auth = NegotiateAuth.new
    @sspi_negotiate_auth = SSPINegotiateAuth.new
    # sort authenticators by priority
    @authenticator = [@negotiate_auth, @sspi_negotiate_auth, @basic_auth]
  end

  def reset_challenge
    @authenticator.each do |auth|
      auth.reset_challenge
    end
  end

  def set_auth(user, passwd)
    @authenticator.each do |auth|
      auth.set(nil, user, passwd)
    end
    reset_challenge
  end

  def filter_request(req)
    @authenticator.each do |auth|
      if cred = auth.get(req)
        req.header.set('Proxy-Authorization', auth.scheme + " " + cred)
        return
      end
    end
  end

  def filter_response(req, res)
    command = nil
    uri = req.header.request_uri
    if res.status == HTTP::Status::PROXY_AUTHENTICATE_REQUIRED
      if challenge = parse_authentication_header(res, 'proxy-authenticate')
        challenge.each do |scheme, param_str|
          @authenticator.each do |auth|
            if scheme.downcase == auth.scheme.downcase
              challengeable = auth.challenge(uri, param_str)
              command = :retry if challengeable
            end
          end
        end
        # ignore unknown authentication scheme
      end
    end
    command
  end
end


# HTTPClient::Site -- manage a site(host and port)
#
class Site      # :nodoc:
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
    sprintf("#<%s:0x%x %s>", self.class.name, __id__, @uri || addr)
  end
end


# HTTPClient::Connection -- magage a connection(one request and response to it).
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


# HTTPClient::SessionManager -- manage several sessions.
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

  attr_reader :test_loopback_http_response

  def initialize(client)
    @client = client
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
    @test_loopback_http_response = []

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
    connect() if @state == :INIT
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
        while true
          begin
            timeout(@receive_timeout) do
              data = read_body()
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
      if retry_number < 5
        retry
      end
      raise BadResponse.new(
        "connect to the server failed with status #{@status} #{@reason}")
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
        raise RuntimeError.new("Unparsable header: '#{line}'.") if $DEBUG
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

  include Util

  attr_reader :agent_name
  attr_reader :from
  attr_reader :ssl_config
  attr_accessor :cookie_manager
  attr_reader :test_loopback_response
  attr_reader :request_filter
  attr_reader :proxy_auth
  attr_reader :www_auth

  class << self
    %w(get_content head get post put delete options propfind trace).each do |name|
      eval <<-EOD
        def #{name}(*arg)
          new.#{name}(*arg)
        end
      EOD
    end
  end

  class RetryableResponse < StandardError   # :nodoc:
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
        raise ArgumentError.new("unsupported proxy `#{proxy}'")
      end
      @proxy_auth.reset_challenge
      if @proxy.user || @proxy.password
        @proxy_auth.set_auth(@proxy.user, @proxy.password)
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
    follow_redirect(uri, query) { |new_uri, new_query|
      get(new_uri, query, extheader, &block)
    }.content
  end

  def post_content(uri, body = nil, extheader = {}, &block)
    follow_redirect(uri, nil) { |new_uri, new_query|
      post(new_uri, body, extheader, &block)
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

  def propfind(uri, query = nil, body = nil, extheader = PROPFIND_DEFAULT_EXTHEADER, &block)
    request('PROPFIND', uri, query, body, extheader, &block)
  end
  
  def proppatch(path, body, extheader = {}, &block)
    request('PROPPATCH', uri, query, body, extheader, &block)
  end
  
  def trace(uri, query = nil, body = nil, extheader = {}, &block)
    request('TRACE', uri, query, body, extheader, &block)
  end

  def request(method, uri, query = nil, body = nil, extheader = {}, &block)
    uri = urify(uri)
    conn = Connection.new
    res = nil
    retry_count = 5
    while retry_count > 0
      begin
        prepare_request(method, uri, query, body, extheader) do |req, proxy|
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

  def propfind_async(uri, query = nil, body = nil, extheader = PROPFIND_DEFAULT_EXTHEADER)
    request_async('PROPFIND', uri, query, body, extheader)
  end
  
  def proppatch_async(path, body, extheader = {})
    request_async('PROPPATCH', uri, query, body, extheader)
  end
  
  def trace_async(uri, query = nil, body = nil, extheader = {})
    request_async('TRACE', uri, query, body, extheader)
  end

  def request_async(method, uri, query = nil, body = nil, extheader = {})
    uri = urify(uri)
    conn = Connection.new
    t = Thread.new(conn) { |tconn|
      prepare_request(method, uri, query, body, extheader) do |req, proxy|
        do_get_stream(req, proxy, tconn)
      end
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

  def follow_redirect(uri, query = nil)
    uri = urify(uri)
    retry_number = 0
    while retry_number < 10
      res = yield(uri, query)
      if HTTP::Status.successful?(res.status)
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

  def prepare_request(method, uri, query, body, extheader)
    proxy = no_proxy?(uri) ? nil : @proxy
    begin
      req = create_request(method, uri, query, body, extheader, !proxy.nil?)
      yield(req, proxy)
    rescue Session::KeepAliveDisconnected
      req = create_request(method, uri, query, body, extheader, !proxy.nil?)
      yield(req, proxy)
    end
  end

  def create_request(method, uri, query, body, extheader, proxy)
    if extheader.is_a?(Hash)
      extheader = extheader.to_a
    end
    if @cookie_manager && cookies = @cookie_manager.find(uri)
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
    @request_filter.each do |filter|
      filter.filter_request(req)
    end
    if str = @test_loopback_response.shift
      dump_dummy_request_response(req.body.dump, str) if @debug_dev
      conn.push(HTTP::Message.new_response(str))
      return
    end
    content = ''
    res = HTTP::Message.new_response(content)
    @debug_dev << "= Request\n\n" if @debug_dev
    sess = @session_manager.query(req, proxy)
    res.peer_cert = sess.ssl_peer_cert
    @debug_dev << "\n\n= Response\n\n" if @debug_dev
    do_get_header(req, res, sess)
    conn.push(res)
    sess.get_data() do |part|
      if block
        block.call(part)
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
      conn.push(HTTP::Message.new_response(str))
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
    sess.get_header().each do |line|
      unless /^([^:]+)\s*:\s*(.*)$/ =~ line
        raise RuntimeError.new("Unparsable header: '#{line}'.") if $DEBUG
      end
      res.header.set($1, $2)
    end
    if @cookie_manager && res.header['set-cookie']
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
