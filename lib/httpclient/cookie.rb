require 'http-cookie'

class HTTPClient
  class CookieManager
    attr_reader :format
    attr_accessor :cookies_file

    def initialize(cookies_file = nil, format = WebAgentSaver)
      @cookies_file = cookies_file
      @format = format
      @jar = HTTP::CookieJar.new
      load_cookies if @cookies_file
    end

    def load_cookies
      check_cookies_file
      @jar.clear
      @jar.load(@cookies_file, :format => @format)
    end

    def save_cookies(session = false)
      check_cookies_file
      @jar.save(@cookies_file, :format => @format, :session => session)
    end

    def cookies(uri = nil)
      cookies = @jar.cookies(uri)
      cookies.empty? ? nil : cookies
    end

    def parse(value, uri)
      @jar.parse(value, uri)
    end

    def cookies=(cookies)
      @jar.clear
      cookies.each do |cookie|
        add(cookie)
      end
    end

    def add(cookie)
      @jar.add(cookie)
    end

    def find(uri)
      if cookie = cookies(uri)
        HTTP::Cookie.cookie_value(cookie)
      end
    end

    def flag(cookie)
      WebAgentSaver.flag(cookie)
    end

  private

    def check_cookies_file
      unless @cookies_file
        raise ArgumentError.new('Cookies file not specified')
      end
    end
  end

  class WebAgentSaver < HTTP::CookieJar::AbstractSaver
    def default_options
      {} # TODO
    end

    def save(io, jar)
      jar.each { |cookie|
        next if !@session && cookie.session?
        io.print cookie_to_record(cookie)
      }
    end

    def load(io, jar)
      io.each_line { |line|
        cookie = parse_record(line) and jar.add(cookie)
      }
    end

  private

    def cookie_to_record(cookie)
      [
        cookie.origin,
        cookie.name, 
        cookie.value,
        cookie.expires.to_i,
        cookie.dot_domain,
        cookie.path,
        self.class.flag(cookie)
      ].join("\t") + "\n"
    end

    def parse_record(line)
      return nil if /\A#/ =~ line
      col = line.chomp.split(/\t/)

      origin = col[0]
      name = col[1]
      value = col[2]
      value.chomp!
      if col[3].empty? or col[3] == '0'
        expires = nil
      else
        expires = Time.at(col[3].to_i)
        return nil if expires < Time.now
      end
      domain = col[4]
      path = col[5]

      cookie = HTTP::Cookie.new(name, value,
        :origin => origin,
        :domain => domain,
        :path => path,
        :expires => expires)
      self.class.set_flag(cookie, col[6].to_i)
      cookie
    end

    USE = 1
    SECURE = 2
    DOMAIN = 4
    PATH = 8
    HTTP_ONLY = 64

    def self.flag(cookie)
      flg = 0
      flg += USE # not used
      flg += SECURE  if cookie.secure?
      flg += DOMAIN  if cookie.for_domain?
      flg += HTTP_ONLY  if cookie.httponly?
      flg += PATH  if cookie.path # not used
      flg
    end

    def self.set_flag(cookie, flag)
      cookie.secure = true if flag & SECURE > 0
      cookie.for_domain = true if flag & DOMAIN > 0
      cookie.httponly = true if flag & HTTP_ONLY > 0
    end
  end
end

# for backward compatibility
class WebAgent
  CookieManager = ::HTTPClient::CookieManager
end
