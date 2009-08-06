# HTTPClient - HTTP client library.
# Copyright (C) 2000-2009  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.
#
# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


require 'digest/md5'
require 'httpclient/session'


class HTTPClient

  begin
    require 'net/ntlm'
    NTLMEnabled = true
  rescue LoadError
    NTLMEnabled = false
  end

  begin
    require 'win32/sspi'
    SSPIEnabled = true
  rescue LoadError
    SSPIEnabled = false
  end


  # Common abstract class for authentication filter.
  #
  # There are 2 authentication filters.
  # WWWAuth:: Authentication filter for handling authentication negotiation
  #           between Web server.  Parses 'WWW-Authentication' header in
  #           response and generates 'Authorization' header in request.
  # ProxyAuth:: Authentication filter for handling authentication negotiation
  #             between Proxy server.  Parses 'Proxy-Authentication' header in
  #             response and generates 'Proxy-Authorization' header in request.
  class AuthFilterBase
  private

    def parse_authentication_header(res, tag)
      challenge = res.header[tag]
      return nil unless challenge
      challenge.collect { |c| parse_challenge_header(c) }.compact
    end

    def parse_challenge_header(challenge)
      scheme, param_str = challenge.scan(/\A(\S+)(?:\s+(.*))?\z/)[0]
      return nil if scheme.nil?
      return scheme, param_str
    end
  end


  # Authentication filter for handling authentication negotiation between
  # Web server.  Parses 'WWW-Authentication' header in response and
  # generates 'Authorization' header in request.
  #
  # Authentication filter is implemented using request filter of HTTPClient.
  # It traps HTTP response header and maintains authentication state, and
  # traps HTTP request header for inserting necessary authentication header.
  #
  # WWWAuth has sub filters (BasicAuth, DigestAuth, NegotiateAuth and
  # SSPINegotiateAuth) and delegates some operations to it.
  # NegotiateAuth requires 'ruby/ntlm' module.
  # SSPINegotiateAuth requires 'win32/sspi' module.
  class WWWAuth < AuthFilterBase
    attr_reader :basic_auth
    attr_reader :digest_auth
    attr_reader :negotiate_auth
    attr_reader :sspi_negotiate_auth
    attr_reader :oauth

    # Creates new WWWAuth.
    def initialize
      @basic_auth = BasicAuth.new
      @digest_auth = DigestAuth.new
      @negotiate_auth = NegotiateAuth.new
      @sspi_negotiate_auth = SSPINegotiateAuth.new
      @oauth = OAuth.new
      # sort authenticators by priority
      @authenticator = [@oauth, @negotiate_auth, @sspi_negotiate_auth, @digest_auth, @basic_auth]
    end

    # Resets challenge state.  See sub filters for more details.
    def reset_challenge
      @authenticator.each do |auth|
        auth.reset_challenge
      end
    end

    # Set authentication credential.  See sub filters for more details.
    def set_auth(uri, user, passwd)
      @authenticator.each do |auth|
        auth.set(uri, user, passwd)
      end
      reset_challenge
    end

    # Filter API implementation.  Traps HTTP request and insert
    # 'Authorization' header if needed.
    def filter_request(req)
      @authenticator.each do |auth|
        if cred = auth.get(req)
          req.header.set('Authorization', auth.scheme + " " + cred)
          return
        end
      end
    end

    # Filter API implementation.  Traps HTTP response and parses
    # 'WWW-Authenticate' header.
    def filter_response(req, res)
      command = nil
      if res.status == HTTP::Status::UNAUTHORIZED
        if challenge = parse_authentication_header(res, 'www-authenticate')
          uri = req.header.request_uri
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


  # Authentication filter for handling authentication negotiation between
  # Proxy server.  Parses 'Proxy-Authentication' header in response and
  # generates 'Proxy-Authorization' header in request.
  #
  # Authentication filter is implemented using request filter of HTTPClient.
  # It traps HTTP response header and maintains authentication state, and
  # traps HTTP request header for inserting necessary authentication header.
  #
  # ProxyAuth has sub filters (BasicAuth, NegotiateAuth, and SSPINegotiateAuth)
  # and delegates some operations to it.
  # NegotiateAuth requires 'ruby/ntlm' module.
  # SSPINegotiateAuth requires 'win32/sspi' module.
  class ProxyAuth < AuthFilterBase
    attr_reader :basic_auth
    attr_reader :negotiate_auth
    attr_reader :sspi_negotiate_auth

    # Creates new ProxyAuth.
    def initialize
      @basic_auth = BasicAuth.new
      @negotiate_auth = NegotiateAuth.new
      @sspi_negotiate_auth = SSPINegotiateAuth.new
      # sort authenticators by priority
      @authenticator = [@negotiate_auth, @sspi_negotiate_auth, @basic_auth]
    end

    # Resets challenge state.  See sub filters for more details.
    def reset_challenge
      @authenticator.each do |auth|
        auth.reset_challenge
      end
    end

    # Set authentication credential.  See sub filters for more details.
    def set_auth(user, passwd)
      @authenticator.each do |auth|
        auth.set(nil, user, passwd)
      end
      reset_challenge
    end

    # Filter API implementation.  Traps HTTP request and insert
    # 'Proxy-Authorization' header if needed.
    def filter_request(req)
      @authenticator.each do |auth|
        if cred = auth.get(req)
          req.header.set('Proxy-Authorization', auth.scheme + " " + cred)
          return
        end
      end
    end

    # Filter API implementation.  Traps HTTP response and parses
    # 'Proxy-Authenticate' header.
    def filter_response(req, res)
      command = nil
      if res.status == HTTP::Status::PROXY_AUTHENTICATE_REQUIRED
        if challenge = parse_authentication_header(res, 'proxy-authenticate')
          uri = req.header.request_uri
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

  # Authentication filter for handling BasicAuth negotiation.
  # Used in WWWAuth and ProxyAuth.
  class BasicAuth
    include HTTPClient::Util

    # Authentication scheme.
    attr_reader :scheme

    # Creates new BasicAuth filter.
    def initialize
      @cred = nil
      @auth = {}
      @challengeable = {}
      @scheme = "Basic"
    end

    # Resets challenge state.  Do not send '*Authorization' header until the
    # server sends '*Authentication' again.
    def reset_challenge
      @challengeable.clear
    end

    # Set authentication credential.
    # uri == nil for generic purpose (allow to use user/password for any URL).
    def set(uri, user, passwd)
      if uri.nil?
        @cred = ["#{user}:#{passwd}"].pack('m').tr("\n", '')
      else
        uri = Util.uri_dirname(uri)
        @auth[uri] = ["#{user}:#{passwd}"].pack('m').tr("\n", '')
      end
    end

    # Response handler: returns credential.
    # It sends cred only when a given uri is;
    # * child page of challengeable(got *Authenticate before) uri and,
    # * child page of defined credential
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

    # Challenge handler: remember URL for response.
    def challenge(uri, param_str = nil)
      @challengeable[urify(uri)] = true
      true
    end
  end


  # Authentication filter for handling DigestAuth negotiation.
  # Used in WWWAuth.
  class DigestAuth
    # Authentication scheme.
    attr_reader :scheme

    # Creates new DigestAuth filter.
    def initialize
      @auth = {}
      @challenge = {}
      @nonce_count = 0
      @scheme = "Digest"
    end

    # Resets challenge state.  Do not send '*Authorization' header until the
    # server sends '*Authentication' again.
    def reset_challenge
      @challenge.clear
    end

    # Set authentication credential.
    # uri == nil is ignored.
    def set(uri, user, passwd)
      if uri
        uri = Util.uri_dirname(uri)
        @auth[uri] = [user, passwd]
      end
    end

    # Response handler: returns credential.
    # It sends cred only when a given uri is;
    # * child page of challengeable(got *Authenticate before) uri and,
    # * child page of defined credential
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

    # Challenge handler: remember URL and challenge token for response.
    def challenge(uri, param_str)
      @challenge[uri] = parse_challenge_param(param_str)
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
      nonce = param['nonce']
      cnonce = generate_cnonce()
      @nonce_count += 1
      message_digest = []
      message_digest << Digest::MD5.hexdigest(a_1)
      message_digest << nonce
      message_digest << ('%08x' % @nonce_count)
      message_digest << cnonce
      message_digest << param['qop']
      message_digest << Digest::MD5.hexdigest(a_2)
      header = []
      header << "username=\"#{user}\""
      header << "realm=\"#{param['realm']}\""
      header << "nonce=\"#{nonce}\""
      header << "uri=\"#{uri.path}\""
      header << "cnonce=\"#{cnonce}\""
      header << "nc=#{'%08x' % @nonce_count}"
      header << "qop=\"#{param['qop']}\""
      header << "response=\"#{Digest::MD5.hexdigest(message_digest.join(":"))}\""
      header << "algorithm=\"MD5\""
      header << "opaque=\"#{param['opaque']}\"" if param.key?('opaque')
      header.join(", ")
    end

    # cf. WEBrick::HTTPAuth::DigestAuth#generate_next_nonce(aTime)
    def generate_cnonce
      now = "%012d" % Time.now.to_i
      pk = Digest::MD5.hexdigest([now, self.__id__, Process.pid, rand(65535)].join)[0, 32]
      [now + ':' + pk].pack('m*').chop
    end

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
  end


  # Authentication filter for handling Negotiate/NTLM negotiation.
  # Used in WWWAuth and ProxyAuth.
  #
  # NegotiateAuth depends on 'ruby/ntlm' module.
  class NegotiateAuth
    # Authentication scheme.
    attr_reader :scheme
    # NTLM opt for ruby/ntlm.  {:ntlmv2 => true} by default.
    attr_reader :ntlm_opt

    # Creates new NegotiateAuth filter.
    def initialize
      @auth = {}
      @auth_default = nil
      @challenge = {}
      @scheme = "Negotiate"
      @ntlm_opt = {
        :ntlmv2 => true
      }
    end

    # Resets challenge state.  Do not send '*Authorization' header until the
    # server sends '*Authentication' again.
    def reset_challenge
      @challenge.clear
    end

    # Set authentication credential.
    # uri == nil for generic purpose (allow to use user/password for any URL).
    def set(uri, user, passwd)
      if uri
        uri = Util.uri_dirname(uri)
        @auth[uri] = [user, passwd]
      else
        @auth_default = [user, passwd]
      end
    end

    # Response handler: returns credential.
    # See ruby/ntlm for negotiation state transition.
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

    # Challenge handler: remember URL and challenge token for response.
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


  # Authentication filter for handling Negotiate/NTLM negotiation.
  # Used in ProxyAuth.
  #
  # SSPINegotiateAuth depends on 'win32/sspi' module.
  class SSPINegotiateAuth
    # Authentication scheme.
    attr_reader :scheme

    # Creates new SSPINegotiateAuth filter.
    def initialize
      @challenge = {}
      @scheme = "Negotiate"
    end

    # Resets challenge state.  Do not send '*Authorization' header until the
    # server sends '*Authentication' again.
    def reset_challenge
      @challenge.clear
    end

    # Set authentication credential.
    # NOT SUPPORTED: username and necessary data is retrieved by win32/sspi.
    # See win32/sspi for more details.
    def set(uri, user, passwd)
      # not supported
    end

    # Response handler: returns credential.
    # See win32/sspi for negotiation state transition.
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
        return authenticator.get_initial_token(@scheme)
      when :response
        @challenge.delete(domain_uri)
        return authenticator.complete_authentication(authphrase)
      end
      nil
    end

    # Challenge handler: remember URL and challenge token for response.
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

  # Authentication filter for handling OAuth negotiation.
  # Used in WWWAuth.
  #
  # CAUTION: This impl only support '#7 Accessing Protected Resources' in OAuth
  # Core 1.0 spec for now. You need to obtain Access token and Access secret by
  # yourself.
  #
  # CAUTION: This impl does NOT support OAuth Request Body Hash spec for now.
  # http://oauth.googlecode.com/svn/spec/ext/body_hash/1.0/oauth-bodyhash.html
  #
  class OAuth
    include HTTPClient::Util

    # Authentication scheme.
    attr_reader :scheme

    class Config
      include HTTPClient::Util

      attr_accessor :realm
      attr_accessor :consumer_key
      attr_accessor :consumer_secret
      attr_accessor :token
      attr_accessor :secret
      attr_accessor :signature_method
      attr_accessor :version
      attr_reader :signature_handler

      attr_accessor :debug_timestamp
      attr_accessor :debug_nonce

      def initialize(*args)
        @realm,
          @consumer_key,
          @consumer_secret,
          @token,
          @secret,
          @signature_method,
          @version =
        keyword_argument(args,
          :realm,
          :consumer_key,
          :consumer_secret,
          :token,
          :secret,
          :signature_method,
          :version
        )
        @signature_handler = {}
      end
    end

    def self.escape(str) # :nodoc:
      str.gsub(/([^a-zA-Z0-9_.~-]+)/n) {
        '%' + $1.unpack('H2' * $1.size).join('%').upcase
      }
    end

    def escape(str)
      self.class.escape(str)
    end

    # Creates new DigestAuth filter.
    def initialize
      @auth = {}
      @challengeable = {}
      @nonce_count = 0
      @signature_handler = {
        'HMAC-SHA1' => method(:sign_hmac_sha1)
      }
      @scheme = "OAuth"
    end

    # Resets challenge state.  Do not send '*Authorization' header until the
    # server sends '*Authentication' again.
    def reset_challenge
      @challengeable.clear
    end

    # Set authentication credential.
    # You cannot set OAuth config via WWWAuth#set_auth. Use OAuth#config=
    def set(uri, user, passwd)
      # not supported
    end

    # Set authentication credential.
    def set_config(uri, config)
      if uri
        uri = Util.uri_dirname(urify(uri))
        @auth[uri] = config
      end
    end

    # Response handler: returns credential.
    # It sends cred only when a given uri is;
    # * child page of challengeable(got *Authenticate before) uri and,
    # * child page of defined credential
    def get(req)
      target_uri = req.header.request_uri
      return nil unless @challengeable.find { |uri, ok|
        Util.uri_part_of(target_uri, uri) and ok
      }
      config = Util.hash_find_value(@auth) { |uri, cred|
        Util.uri_part_of(target_uri, uri)
      }
      return nil unless config
      calc_cred(req, config)
    end

    # Challenge handler: remember URL for response.
    def challenge(uri, param_str = nil)
      @challengeable[urify(uri)] = true
      true
    end

  private

    def calc_cred(req, config)
      header = {}
      header['oauth_consumer_key'] = config.consumer_key
      header['oauth_token'] = config.token
      header['oauth_signature_method'] = config.signature_method
      header['oauth_timestamp'] = config.debug_timestamp || Time.now.to_i.to_s
      header['oauth_nonce'] = config.debug_nonce || generate_nonce()
      header['oauth_version'] = config.version if config.version
      signature = sign(config, header, req)
      header['oauth_signature'] = signature
      str = header.map { |k, v| encode_header(k, v) }.join(', ')
      if config.realm
        str = %Q(realm="#{config.realm}", ) + str
      end
      str
    end

    def generate_nonce
      @nonce_count += 1
      now = "%012d" % Time.now.to_i
      pk = Digest::MD5.hexdigest([@nonce_count.to_s, now, self.__id__, Process.pid, rand(65535)].join)[0, 32]
      [now + ':' + pk].pack('m*').chop
    end

    def encode_header(k, v)
      %Q(#{escape(k.to_s)}="#{escape(v.to_s)}")
    end

    def encode_param(params)
      params.map { |k, v|
        %Q(#{escape(k.to_s)}=#{escape(v.to_s)})
      }
    end

    def sign(config, header, req)
      base_string = create_base_string(config, header, req)
      if handler = config.signature_handler[config.signature_method] || @signature_handler[config.signature_method.to_s]
        handler.call(config, base_string)
      else
        raise ConfigurationError.new("Unknown OAuth signature method: #{config.signature_method}")
      end
    end

    def create_base_string(config, header, req)
      params = encode_param(header)
      query = req.header.request_query
      if query and HTTP::Message.multiparam_query?(query)
        params += encode_param(query)
      end
      # captures HTTP Message body only for 'application/x-www-form-urlencoded'
      if req.header.contenttype == 'application/x-www-form-urlencoded' and req.body.size
        params += encode_param(HTTP::Message.parse(req.body.content))
      end
      uri = req.header.request_uri
      if uri.query
        params += encode_param(HTTP::Message.parse(uri.query))
      end
      if uri.port == uri.default_port
        request_url = "#{uri.scheme.downcase}://#{uri.host}#{uri.path}"
      else
        request_url = "#{uri.scheme.downcase}://#{uri.host}:#{uri.port}#{uri.path}"
      end
      [req.header.request_method.upcase, request_url, params.sort.join('&')].map { |e|
        escape(e)
      }.join('&')
    end

    def sign_hmac_sha1(config, base_string)
      unless SSLEnabled
        raise ConfigurationError.new("openssl required for OAuth implementation")
      end
      key = [escape(config.consumer_secret), escape(config.secret)].join('&')
      digester = OpenSSL::Digest::SHA1.new
      [OpenSSL::HMAC.digest(digester, key, base_string)].pack('m*').chomp
    end
  end


end
