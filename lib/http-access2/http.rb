# HTTP - HTTP container.
# Copyright (C) 2001, 2002, 2003 NAKAMURA, Hiroshi.
#
# This module is copyrighted free software by NAKAMURA, Hiroshi.
# You can redistribute it and/or modify it under the same term as Ruby.

require 'uri'


module HTTP


module Status
  OK = 200
  MOVED_PERMANENTLY = 301
  FOUND = 302
  SEE_OTHER = 303
  TEMPORARY_REDIRECT = MOVED_TEMPORARILY = 307
  BAD_REQUEST = 400
  INTERNAL = 500

  def self.redirect?(status)
    [
      MOVED_PERMANENTLY, FOUND, SEE_OTHER,
      TEMPORARY_REDIRECT, MOVED_TEMPORARILY
    ].include?(status)
  end
end


class Error < StandardError; end
class BadResponseError < Error; end

  class << self
    def http_date(a_time)
      a_time.gmtime.strftime("%a, %d %b %Y %H:%M:%S GMT")
    end

    ProtocolVersionRegexp = Regexp.new('^(?:HTTP/|)(\d+)\.(\d+)$')
    def keep_alive_enabled?(version)
      ProtocolVersionRegexp =~ version
      if ($1 && ($1.to_i > 1))
	true
      elsif ($2 && ($2.to_i >= 1))
	true
      else
	false
      end
    end
  end


# HTTP::Message -- HTTP message.
# 
# DESCRIPTION
#   A class that describes 1 HTTP request / response message.
#
class Message
  CRLF = "\r\n"

  # HTTP::Message::Headers -- HTTP message header.
  # 
  # DESCRIPTION
  #   A class that describes header part of HTTP message.
  #
  class Headers
    # HTTP version string in a HTTP header.
    attr_accessor :http_version
    # Content-type.
    attr_accessor :body_type
    # Charset.
    attr_accessor :body_charset
    # Size of body.
    attr_reader :body_size
    # A milestone of body.
    attr_accessor :body_date
    # Chunked or not.
    attr_reader :chunked
    # Request method.
    attr_reader :request_method
    # Requested URI.
    attr_reader :request_uri
    # HTTP status reason phrase.
    attr_accessor :reason_phrase

    StatusCodeMap = {
      Status::OK => 'OK',
      Status::MOVED_PERMANENTLY => 'Moved Permanently',
      Status::TEMPORARY_REDIRECT => 'Temporary Redirect',
      Status::MOVED_TEMPORARILY => 'Temporary Redirect',
      Status::BAD_REQUEST => 'Bad Request',
      Status::INTERNAL => 'Internal Server Error',
    }

    CharsetMap = {
      'NONE' => 'us-ascii',
      'EUC'  => 'euc-jp',
      'SJIS' => 'shift_jis',
      'UTF8' => 'utf-8',
    }

    # SYNOPSIS
    #   HTTP::Message.new
    #
    # ARGS
    #   N/A
    #
    # DESCRIPTION
    #   Create a instance of HTTP request or HTTP response.  Specify
    #   status_code for HTTP response.
    #
    def initialize
      @is_request = nil	# true, false and nil
      @http_version = 'HTTP/1.1'
      @body_type = nil
      @body_charset = nil
      @body_size = nil
      @body_date = nil
      @header_item = []
      @chunked = false
      @response_status_code = nil
      @reason_phrase = nil
      @request_method = nil
      @request_uri = nil
      @request_query = nil
      @request_via_proxy = nil
    end

    def init_request(method, uri, query = nil, via_proxy = nil)
      @is_request = true
      @request_method = method
      @request_uri = if uri.is_a?(URI)
	  uri
	else
	  URI.parse(uri.to_s)
	end
      @request_query = create_query_uri(@request_uri, query)
      @request_via_proxy = via_proxy
    end

    def init_response(status_code)
      @is_request = false
      self.response_status_code = status_code
    end

    attr_accessor :request_via_proxy

    attr_reader :response_status_code
    def response_status_code=(status_code)
      @response_status_code = status_code
      @reason_phrase = StatusCodeMap[@response_status_code]
    end

    def contenttype
      self['content-type'][0]
    end

    def contenttype=(contenttype)
      self['content-type'] = contenttype
    end

    # body_size == nil means that the body is_a? IO
    def body_size=(body_size)
      @body_size = body_size
      if @body_size
	@chunked = false
      else
	@chunked = true
      end
    end

    def dump(dev = '')
      set_header
      if @is_request
	dev << request_line
      else
	dev << response_status_line
      end
      dev << @header_item.collect { |key, value|
	  dump_line("#{ key }: #{ value }")
	}.join
      dev
    end

    def set(key, value)
      @header_item.push([key, value])
    end

    def get(key = nil)
      if !key
	@header_item
      else
	@header_item.find_all { |pair| pair[0].upcase == key.upcase }
      end
    end

    def []=(key, value)
      set(key, value)
    end

    def [](key)
      get(key).collect { |item| item[1] }
    end

  private

    def request_line
      path = if @request_via_proxy
	if @request_uri.port
	  "#{ @request_uri.scheme }://#{ @request_uri.host }:#{ @request_uri.port }#{ @request_query }"
	else
	  "#{ @request_uri.scheme }://#{ @request_uri.host }#{ @request_query }"
	end
      else
	@request_query
      end
      dump_line("#{ @request_method } #{ path } #{ @http_version }")
    end

    def response_status_line
      if defined?(Apache)
	dump_line("#{ @http_version } #{ response_status_code } #{ @reason_phrase }")
      else
	dump_line("Status: #{ response_status_code } #{ @reason_phrase }")
      end
    end

    def set_header
      if defined?(Apache)
	set('Date', HTTP.http_date(Time.now))
      end

      unless HTTP.keep_alive_enabled?(@http_version)
	set('Connection', 'close')
      end

      if @chunked
	set('Transfer-Encoding', 'chunked')
      else
	set('Content-Length', @body_size.to_s)
      end

      if @body_date
	set('Last-Modified', HTTP.http_date(@body_date))
      end

      if @is_request == true
	set('Host', @request_uri.host)
      elsif @is_request == false
	set('Content-Type', "#{ @body_type || 'text/html' }; charset=#{ CharsetMap[@body_charset || $KCODE] }")
      end
    end

    def dump_line(str)
      str + CRLF
    end

    def create_query_uri(uri, query)
      path = uri.path.dup
      path = '/' if path.empty?
      query_str = nil
      if uri.query
	query_str = uri.query
      end
      if query
	if query_str
	  query_str << '&' << Message.create_query_part_str(query)
	else
	  query_str = Message.create_query_part_str(query)
	end
      end
      if query_str
	path << '?' << query_str
      end
      path
    end
  end

  class Body
    attr_accessor :type, :charset, :date, :chunk_size

    def initialize(body = nil, date = nil, type = nil, charset = nil)
      @body = nil
      set_content(body || '')
      @type = type
      @charset = charset
      @date = date
      @chunk_size = 4096
    end

    def size
      if @body.is_a?(IO)
	nil
      else
	@body.size
      end
    end

    def dump(dev = '')
      if size.nil?
	begin
	  while true
	    chunk = @body.sysread(@chunk_size)
	    dev << dump_chunk(chunk)
	  end
	rescue EOFError
	ensure
	  dev << (dump_last_chunk + CRLF)
	end
      else
	dev << @body
      end
      dev
    end

    def content
      @body
    end

    def set_content(body)
      case body
      when IO
	@body = body
      when Array, Hash
	@body = Message.create_query_part_str(body)
      else
	@body = body
      end
    end

  private

    def dump_chunk(str)
      dump_chunk_size(str.size) << (str + CRLF)
    end

    def dump_last_chunk
      dump_chunk_size(0)
    end

    def dump_chunk_size(size)
      sprintf("%x", size) << CRLF
    end
  end

  def initialize
    @body = @header = nil
  end

  class << self
    alias __new new
    undef new
  end

  def self.new_request(method, uri, query = nil, body = nil, proxy = nil)
    m = self.__new
    m.header = Headers.new
    m.header.init_request(method, uri, query, proxy)
    m.body = Body.new(body)
    m
  end

  def self.new_response(body = '')
    m = self.__new
    m.header = Headers.new
    m.header.init_response(Status::OK)
    m.body = Body.new(body)
    m
  end

  def dump(dev = '')
    sync_header
    dev = header.dump(dev)
    dev << CRLF
    dev = body.dump(dev) if body
    dev
  end

  def load(str)
    buf = str.dup
    unless self.header.load(buf)
      self.body.load(buf)
    end
  end

  def header
    @header
  end

  def header=(header)
    @header = header
    sync_body
  end

  def content
    @body.content
  end

  def body
    @body
  end

  def body=(body)
    @body = body
    sync_header
  end

  def status
    @header.response_status_code
  end

  def status=(status)
    @header.response_status_code = status
  end

  def version
    @header.http_version
  end

  def version=(version)
    @header.http_version = version
  end

  def reason
    @header.reason_phrase
  end

  def reason=(reason)
    @header.reason_phrase = reason
  end

  def contenttype
    @header.contenttype
  end

  def contenttype=(contenttype)
    @header.contenttype = contenttype
  end

  class << self
    def create_query_part_str(query)
      return case query
	when Array, Hash
	  escape_query(query)
	when NilClass
	  nil
	else
	  query.to_s
	end
    end

    def escape_query(query)
      query.collect { |attr, value|
	escape(attr.to_s) << '=' << escape(value.to_s)
      }.join('&')
    end

    # from CGI.escape
    def escape(str)
      str.gsub(/([^ a-zA-Z0-9_.-]+)/n) {
  	'%' + $1.unpack('H2' * $1.size).join('%').upcase
      }.tr(' ', '+')
    end
  end

private

  def sync_header
    if @header and @body
      @header.body_type = @body.type
      @header.body_charset = @body.charset
      @header.body_size = @body.size
      @header.body_date = @body.date
    end
  end

  def sync_body
    if @header and @body
      @body.type = @header.body_type
      @body.charset = @header.body_charset
      @body.size = @header.body_size
      @body.date = @header.body_date
    end
  end
end


end
