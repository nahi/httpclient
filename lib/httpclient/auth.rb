# HTTPClient - HTTP client library.
# Copyright (C) 2000-2008  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.

# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


require 'digest/md5'


class HTTPClient


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


  class AuthFilterBase
    def reset_challenge
      raise NotImplementedError
    end

    def filter_request(req)
      raise NotImplementedError
    end

    def filter_response(req, res)
      raise NotImplementedError
    end

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


  class WWWAuth < AuthFilterBase
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


  class ProxyAuth < AuthFilterBase
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

  # HTTPClient::BasicAuth -- BasicAuth repository.
  #
  class BasicAuth
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
  class DigestAuth
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
  class NegotiateAuth
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
  class SSPINegotiateAuth
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


end
