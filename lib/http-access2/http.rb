# HTTP - HTTP container.
# Copyright (C) 2001, 2002 NAKAMURA, Hiroshi.
#
# This module is copyrighted free software by NAKAMURA, Hiroshi.
# You can redistribute it and/or modify it under the same term as Ruby.

require 'uri'


module HTTP


module Status
  OK = 200
  MOVED_PERMANENTLY = 301
  MOVED_TEMPORARILY = 302
  BAD_REQUEST = 400
  INTERNAL = 500
end


class Error < StandardError; end
class BadResponseError < Error; end

  class << self
    def httpDate( aTime )
      aTime.gmtime.strftime( "%a, %d %b %Y %H:%M:%S GMT" )
    end

    ProtocolVersionRegexp = Regexp.new( '^(?:HTTP/|)(\d+)\.(\d+)$' )
    def keepAliveEnabled?( version )
      ProtocolVersionRegexp =~ version
      if ( $1 && ( $1.to_i > 1 ))
	true
      elsif ( $2 && ( $2.to_i >= 1 ))
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
    attr_accessor :httpVersion
    # Content-type.
    attr_accessor :bodyType
    # Charset.
    attr_accessor :bodyCharset
    # Size of body.
    attr_reader :bodySize
    # A milestone of body.
    attr_accessor :bodyDate
    # Chunked or not.
    attr_reader :chunked
    # Request method.
    attr_reader :requestMethod
    # Requested URI.
    attr_reader :requestUri
    # HTTP status reason phrase.
    attr_accessor :reasonPhrase

    StatusCodeMap = {
      Status::OK => 'OK',
      Status::MOVED_PERMANENTLY => 'Object moved',
      Status::MOVED_TEMPORARILY => 'Object moved',
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
    #   statusCode for HTTP response.
    #
    def initialize
      @isRequest = nil	# true, false and nil
      @httpVersion = 'HTTP/1.1'
      @bodyType = nil
      @bodyCharset = nil
      @bodySize = nil
      @bodyDate = nil
      @headerItem = []
      @chunked = false
      @responseStatusCode = nil
      @reasonPhrase = nil
      @requestMethod = nil
      @requestUri = nil
      @requestQueryUri = nil
      @requestViaProxy = false
    end

    def initRequest( method, uri, query = nil, viaProxy = false )
      @isRequest = true
      @requestMethod = method
      @requestUri = if uri.is_a?( URI )
	  uri
	else
	  URI.parse( uri.to_s )
	end
      @requestQueryUri = createQueryUri( @requestUri, query )
      @requestViaProxy = viaProxy
    end

    def initResponse( statusCode )
      @isRequest = false
      self.responseStatusCode = statusCode
    end

    attr_accessor :requestViaProxy

    attr_reader :responseStatusCode
    def responseStatusCode=( statusCode )
      @responseStatusCode = statusCode
      @reasonPhrase = StatusCodeMap[ @responseStatusCode ]
    end

    def bodySize=( bodySize )
      @bodySize = bodySize
      if @bodySize
	@chunked = false
      else
	@chunked = true
      end
    end

    def dump
      setHeader
      str = ""
      if @isRequest
	str << requestLine
      else
	str << responseStatusLine
      end
      @headerItem.each do | key, value |
	str << dumpLine( "#{ key }: #{ value }" )
      end
      str
    end

    def set( key, value )
      @headerItem.push( [ key, value ] )
    end

    def get( key = nil )
      if !key
	@headerItem
      else
	@headerItem.find_all { | pair | pair[ 0 ].upcase == key.upcase }
      end
    end

    def []=( key, value )
      set( key, value )
    end

    def []( key )
      get( key ).collect { |item| item[ 1 ] }
    end

  private

    def requestLine
      path = unless @requestViaProxy
	  @requestQueryUri
	else
	  if @requestUri.port
	    "http://#{ @requestUri.host }:#{ @requestUri.port }#{ @requestQueryUri }"
	  else
	    "http://#{ @requestUri.host }#{ @requestQueryUri }"
	  end
	end
      dumpLine( "#{ @requestMethod } #{ path } #{ @httpVersion }" )
    end

    def responseStatusLine
      if defined?( Apache )
	dumpLine( "#{ @httpVersion } #{ responseStatusCode } #{ @reasonPhrase }" )
      else
	dumpLine( "Status: #{ responseStatusCode } #{ @reasonPhrase }" )
      end
    end

    def setHeader
      if defined?( Apache )
	set( 'Date', HTTP.httpDate( Time.now ))
      end

      unless HTTP.keepAliveEnabled?( @httpVersion )
	set( 'Connection', 'close' )
      end

      if @chunked
	set( 'Transfer-Encoding', 'chunked' )
      else
	set( 'Content-Length', @bodySize.to_s )
      end

      if @bodyDate
	set( 'Last-Modified', HTTP.httpDate( @bodyDate ))
      end

      if @isRequest == true
	set( 'Host', @requestUri.host )
      elsif @isRequest == false
	set( 'Content-Type', "#{ @bodyType || 'text/html' }; charset=#{ CharsetMap[ @bodyCharset || $KCODE ] }" )
      end
    end

    def dumpLine( str )
      str + CRLF
    end

    def createQueryUri( uri, query )
      path = uri.path.dup
      path = '/' if path.empty?
      queryStr = nil
      if uri.query
	queryStr = uri.query
      end
      if query
	if queryStr
	  queryStr << '&' << createQueryPartStr( query )
	else
	  queryStr = Message.createQueryPartStr( query )
	end
      end
      if queryStr
	path << '?' << queryStr
      end
      path
    end

  end

  class Body
    attr_accessor :type, :charset, :date

    def initialize( body = nil, date = nil, type = nil, charset = nil )
      @body = body || ''
      @type = type
      @charset = charset
      @date = date
    end

    def size
      if @body.is_a?( IO )
	nil
      else
	@body.size
      end
    end

    def dump
      @body
    end

    def load( str )
      @body << str
    end

    def content
      @body
    end
  end

  def initialize
    @body = @header = nil
    @chunkSize = 102400
  end

  class << self
    alias __new new
    undef new
  end

  def self.newRequest( method, uri, query = nil, body = nil, proxy = nil )
    m = self.__new
    m.header = Headers.new
    m.header.initRequest( method, uri, query, proxy )
    m.body = Body.new( body )
    m
  end

  def self.newResponse( body = '' )
    m = self.__new
    m.header = Headers.new
    m.header.initResponse( Status::OK )
    m.body = Body.new( body )
    m
  end

  def dump( dev = '' )
    syncHeader
    dev << header.dump
    dev << dumpEOH
    if body
      if header.chunked
	while !body.content.eof
	  chunk = body.content.read( @chunkSize )
	  dev << dumpChunk( chunk )
	end
	dev << dumpLastChunk << dumpEOH
      else
	dev << body.dump
      end
    end
    dev
  end

  def load( str )
    buf = str.dup
    unless self.header.load( buf )
      self.body.load( buf )
    end
  end

  def header
    @header
  end

  def header=( header )
    @header = header
    syncBody
  end

  def body
    @body
  end

  def body=( body )
    @body = body
    syncHeader
  end

  def status
    @header.responseStatusCode
  end

  def status=( status )
    @header.responseStatusCode = status
  end

  def version
    @header.httpVersion
  end

  def version=( version )
    @header.httpVersion = version
  end

  def reason
    @header.reasonPhrase
  end

  def reason=( reason )
    @header.reasonPhrase = reason
  end

  class << self
  public
    def createQueryPartStr( query )
      return case query
	when Array, Hash
	  escape_query( query )
	when NilClass
	  nil
	else
	  query.to_s
	end
    end

    def escape_query( query )
      data = ''
      query.each do |attr, value|
	data << '&' if !data.empty?
	data << URI.escape( attr.to_s ) << '=' << URI.escape( value.to_s )
      end
      data
    end
  end

private

  def syncHeader
    if @header and @body
      @header.bodyType = @body.type
      @header.bodyCharset = @body.charset
      @header.bodySize = @body.size
      @header.bodyDate = @body.date
    end
  end

  def syncBody
    if @header and @body
      @body.type = @header.bodyType
      @body.charset = @header.bodyCharset
      @body.size = @header.bodySize
      @body.date = @header.bodyDate
    end
  end

  def dumpEOH
    CRLF
  end

  def dumpChunk( str )
    dumpChunkSize( str.size ) << str << CRLF
  end

  def dumpLastChunk
    dumpChunkSize( 0 )
  end

  def dumpChunkSize( size )
    sprintf( "%x", size ) << CRLF
  end
end


end
