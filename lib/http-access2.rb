# HTTPAccess2 - HTTP accessing library.
# Copyright (C) 2000, 2001, 2002 NAKAMURA, Hiroshi.
# 
# This module is copyrighted free software by NAKAMURA, Hiroshi.
# You can redistribute it and/or modify it under the same term as Ruby.
# 
# http-access2.rb is based on http-access.rb in http-access/0.0.4.  Some part
# of code in http-access.rb was recycled in http-access2.rb.  Those part is
# copyrighted by Maehashi-san who made and distribute http-access/0.0.4. Many
# thanks to Maehashi-san.


# Ruby standard library
require 'singleton'
require 'timeout'
require 'uri'
require 'socket'
require 'thread'

# Extra library
require 'http-access2/http'


module HTTPAccess2


VERSION = '1.1'

RUBY_VERSION_STRING =
  "ruby #{ RUBY_VERSION } (#{ RUBY_RELEASE_DATE }) [#{ RUBY_PLATFORM }]"

/: (\S+),v (\S+)/ =~
  %q$Id: http-access2.rb,v 1.5 2003/02/13 10:33:36 nahi Exp $
RCS_FILE, RCS_REVISION = $1, $2

RS = "\r\n"
FS = "\r\n\t"


# DESCRIPTION
#   HTTPAccess2::Client -- Client to retrieve web resources via HTTP.
#
# How to create your client.
#   1. Create simple client.
#     clnt = HTTPAccess2::Client.new
#
#   2. Accessing resources through HTTP proxy.
#     clnt = HTTPAccess2::Client.new( "http://myproxy:8080" )
#
#   3. Set User-Agent and From in HTTP request header.(nil means "No proxy")
#     clnt = HTTPAccess2::Client.new( nil, "MyAgent", "nahi@keynauts.com" )
#
# How to retrieve web resources.
#   1. Get content of specified URL.
#     puts clnt.getContent( "http://www.ruby-lang.org/en/" )
#
#   2. Do HEAD request.
#     res = clnt.head( uri )
#
#   3. Do GET request with query.
#     res = clnt.get( uri )
#
#   4. Do POST request.
#     res = clnt.post( uri )
#     res = clnt.get|post|head( uri, proxy )
#
class Client
  attr_reader :agentName	# Name of this client.
  attr_reader :from		# Owner of this client.

  attr_accessor :proxy		# Proxy

  attr_reader :debugDev		# Device for dumping log for debugging.

  attr_reader :sessionManager	# Session manager.

  # SYNOPSIS
  #   Client.new( proxy = nil, agentName = nil, from = nil )
  #
  # ARGS
  #   proxy	A String of HTTP proxy URL. ex. "http://proxy:8080"
  #   agentName	A String for "User-Agent" HTTP request header.
  #   from	A String for "From" HTTP request header.
  #
  # DESCRIPTION
  #   Create an instance.
  #
  def initialize( proxy = nil, agentName = nil, from = nil )
    @proxy = proxy
    @agentName = agentName
    @from = from
    @basicAuth = BasicAuth.new

    @debugDev = nil

    @sessionManager = SessionManager.instance
    @sessionManager.agentName = @agentName
    @sessionManager.from = @from
  end

  # SYNOPSIS
  #   Client#debugDev=( dev )
  #
  # ARGS
  #   dev	Device for debugging.  nil for 'no debugging device'
  #
  # DEBT
  #   dev must respond to '<<' method.
  #
  # DESCRIPTION
  #   Set debug device.  Messages for debugging is dumped to the device.
  #
  def debugDev=( dev )
    @debugDev = dev
    @sessionManager.debugDev = dev
  end

  def setBasicAuth( uri, userId, passwd )
    unless uri.is_a?( URI )
      uri = URI.parse( uri )
    end
    @basicAuth.set( uri, userId, passwd )
  end

  # SYNOPSIS
  #   Client#getContent( uri, query = nil, extraHeader = {}, &block = nil )
  #
  # ARGS
  #   uri	anURI or aString of uri to connect.
  #   query	aHash or anArray of query part.  e.g. { "a" => "b" }.
  #   		Give an array to pass multiple value like
  #   		[[ "a" => "b" ], [ "a" => "c" ]].
  #   extraHeader
  #   		aHash of extra headers like { "SOAPAction" => "urn:foo" }.
  #   &block	Give a block to get chunked message-body of response like
  #   		getContent( uri ) { | chunkedBody | ... }
  #   		Size of each chunk might not be the same.
  #
  # DESCRIPTION
  #   Get aString of message-body of response.
  #
  # BUGS
  #   getContent should handle 302, etc.  Not yet.
  #
  def getContent( uri, query = nil, extraHeader = {}, &block )
    retryNumber = 0
    while retryNumber < 10
      res = get( uri, query, extraHeader, &block )
      case res.status
      when HTTP::Status::OK
	return res.content.read
      when HTTP::Status::MOVED_PERMANENTLY, HTTP::Status::MOVED_TEMPORARILY
	uri = res.header[ 'location' ][ 0 ]
	query = nil
	retryNumber += 1
	puts "Redirect to: #{ uri }" if $DEBUG
      else
	raise RuntimeError.new( "Unexpected response: #{ res.header.inspect }" )
      end
    end
    raise RuntimeError.new( "Retry count exceeded." )
  end

  def head( uri, query = nil, extraHeader = {} )
    request( 'HEAD', uri, query, nil, extraHeader )
  end

  def get( uri, query = nil, extraHeader = {}, &block )
    request( 'GET', uri, query, nil, extraHeader, &block )
  end

  def post( uri, body = nil, extraHeader = {}, &block )
    request( 'POST', uri, nil, body, extraHeader, &block )
  end

  def put( uri, body = nil, extraHeader = {}, &block )
    request( 'PUT', uri, nil, body, extraHeader, &block )
  end

  def delete( uri, extraHeader = {}, &block )
    request( 'DELETE', uri, nil, nil, extraHeader, &block )
  end

  def options( uri, extraHeader = {}, &block )
    request( 'OPTIONS', uri, nil, nil, extraHeader, &block )
  end

  def trace( uri, query = nil, body = nil, extraHeader = {}, &block )
    request( 'TRACE', uri, query, body, extraHeader, &block )
  end

  def request( method, uri, query = nil, body = nil, extraHeader = {}, &block )
    @debugDev << "= Request\n\n" if @debugDev
    req = createRequest( method, uri, query, body, extraHeader )
    sess = @sessionManager.query( req, @proxy )
    @debugDev << "\n\n= Response\n\n" if @debugDev
    conn = Connection.new
    begin
      doGet( sess, conn, &block )
    rescue Session::KeepAliveDisconnected
      # Try again.
      req = createRequest( method, uri, query, body, extraHeader )
      sess = @sessionManager.query( req, @proxy )
      doGet( sess, conn, &block )
    end
    conn.pop
  end

  def reset( uri )
    @sessionManager.reset( uri )
  end

  ##
  # Async interface.

  def headAsync( uri, query = nil, extraHeader = {} )
    requestAsync( 'HEAD', uri, query, nil, extraHeader )
  end

  def getAsync( uri, query = nil, extraHeader = {}, &block )
    requestAsync( 'GET', uri, query, nil, extraHeader, &block )
  end

  def postAsync( uri, body = nil, extraHeader = {}, &block )
    requestAsync( 'POST', uri, nil, body, extraHeader, &block )
  end

  def putAsync( uri, body = nil, extraHeader = {}, &block )
    requestAsync( 'PUT', uri, nil, body, extraHeader, &block )
  end

  def deleteAsync( uri, extraHeader = {}, &block )
    requestAsync( 'DELETE', uri, nil, nil, extraHeader, &block )
  end

  def optionsAsync( uri, extraHeader = {}, &block )
    requestAsync( 'OPTIONS', uri, nil, nil, extraHeader, &block )
  end

  def traceAsync( uri, query = nil, body = nil, extraHeader = {}, &block )
    requestAsync( 'TRACE', uri, query, body, extraHeader, &block )
  end

  def requestAsync( method, uri, query = nil, body = nil, extraHeader = {},
      &block )
    @debugDev << "= Request\n\n" if @debugDev
    req = createRequest( method, uri, query, body, extraHeader )
    sess = @sessionManager.query( req, @proxy )
    @debugDev << "\n\n= Response\n\n" if @debugDev
    responseConn = Connection.new
    t = Thread.new( responseConn ) { | conn |
      begin
	doGet( sess, conn, &block )
      rescue Session::KeepAliveDisconnected
       	# Try again.
	req = createRequest( method, uri, query, body, extraHeader )
	sess = @sessionManager.query( req, @proxy )
	doGet( sess, conn, &block )
      end
    }
    responseConn.asyncThread = t
    responseConn
  end

  ##
  # Multiple call interface.

  # ???

private
  def createRequest( method, uri, query, body, extraHeader )
    if extraHeader.is_a?( Hash )
      extraHeader = extraHeader.collect { | key, value | [ key, value ] }
    end
    unless uri.is_a?( URI )
      uri = URI.parse( uri )
    end
    cred = @basicAuth.get( uri )
    if cred
      extraHeader << [ 'Authorization', "Basic " << cred ]
    end
    req = HTTP::Message.newRequest( method, uri, query, body, @proxy )
    extraHeader.each do | key, value |
      req.header.set( key, value )
    end
    req
  end

  # !! CAUTION !!
  #   Method 'doGet' runs under MT conditon. Be careful to change.
  def doGet( sess, conn, &block )
    piper, pipew = IO.pipe
    res = HTTP::Message.newResponse( piper )
    res.version, res.status, res.reason = sess.getStatus
    sess.getHeaders().each do | line |
      unless /^([^:]+)\s*:\s*(.*)$/ =~ line
	raise RuntimeError.new( "Unparsable header: '#{ line }'." ) if $DEBUG
      end
      res.header.set( $1, $2 )
    end
    conn.push( res )
    sess.getData() do | str |
      if block
	block.call( str )
      end
      pipew << str
    end
    pipew.close
    @sessionManager.keep( sess ) unless sess.closed?
  end
end


###
## HTTPAccess2::BasicAuth -- BasicAuth repository
#
class BasicAuth	# :nodoc:
  def initialize
    @auth = {}
  end

  def set( uri, userId, passwd )
    uri = uri.clone
    uri.path = uri.path.sub( /\/[^\/]*$/, '/' )
    @auth[ uri ] = [ "#{ userId }:#{ passwd }" ].pack( 'm' ).strip
  end

  def get( uri )
    @auth.each do | realmUri, cred |
      if (( realmUri.host == uri.host ) and
	  ( realmUri.scheme == uri.scheme ) and
	  ( realmUri.port == uri.port ) and
	  uri.path.index( realmUri.path ) == 0)
	return cred
      end
    end
    nil
  end
end


###
## HTTPAccess2::Site -- manage a site( host and port )
#
class Site	# :nodoc:
  attr_accessor :host
  attr_reader :port

  def initialize( host = 'localhost', port = 0 )
    @host = host
    @port = port.to_i
  end

  def addr
    "http://#{ @host }:#{ @port.to_s }"
  end

  def port=( port )
    @port = port.to_i
  end

  def ==( rhs )
    if rhs.is_a?( Site )
      (( @host == rhs.host ) and ( @port == rhs.port ))
    else
      false
    end
  end
end

###
## HTTPAccess2::Connection -- magage a connection(one request and response to it).
#
class Connection	# :nodoc:
  attr_accessor :asyncThread

  def initialize( headersQueue = [], bodyQueue = [] )
    @headers = headersQueue
    @body = bodyQueue
    @asyncThread = nil
    @queue = Queue.new
  end

  def finished?
    if !@asyncThread
      # Not in async mode.
      true
    elsif @asyncThread.alive?
      # Working...
      false
    else
      # Async thread have been finished.
      @asyncThread.join
      true
    end
  end

  def pop
    @queue.pop
  end

  def push( result )
    @queue.push( result )
  end

  def join
    unless @asyncThread
      false
    else
      @asyncThread.join
    end
  end
end

private

###
## HTTPAccess2::SessionManager -- singleton class to manage several sessions.
#
class SessionManager	# :nodoc:
  include Singleton

  attr_accessor :agentName	# Name of this client.
  attr_accessor :from		# Owner of this client.

  attr_accessor :protocolVersion	# Requested protocol version
  attr_accessor :chunkSize		# Chunk size for chunked request
  attr_accessor :debugDev		# Device for dumping log for debugging

  # Those parameters are not used now...
  attr_accessor :connectTimeout
  attr_accessor :connectRetry		# Maximum retry count.  0 for infinite.
  attr_accessor :sendTimeout
  attr_accessor :receiveTimeout
  attr_accessor :readBlockSize

  def initialize
    @proxy = nil

    @agentName = nil
    @from = nil

    @protocolVersion = nil
    @debugDev = nil
    @chunkSize = 102400

    @connectTimeout = 60
    @connectRetry = 1
    @sendTimeout = 120
    @receiveTimeout = 60	# For each readBlockSize bytes...
    @readBlockSize = 102400

    @sessPool = []
    @sessPoolMutex = Mutex.new
  end

  def proxy=( proxyStr )
    unless proxyStr
      @proxy = nil 
      return
    end
    uri = URI.parse( proxyStr )
    @proxy = Site.new( uri.host, uri.port )
  end

  def query( req, proxyStr )
    destSite = Site.new( req.header.requestUri.host, req.header.requestUri.port )
    proxySite = if proxyStr
  	proxyUri = URI.parse( proxyStr )
  	Site.new( proxyUri.host, proxyUri.port )
      else
	@proxy
      end
    sess = open( destSite, proxySite )
    begin
      sess.query( req )
    rescue
      close( destSite )
      raise
      #sess = open( destSite, proxySite )
      #sess.query( req )
    end

    sess
  end

  def reset( uri )
    unless uri.is_a?( URI )
      uri = URI.parse( uri.to_s )
    end
    site = Site.new( uri.host, uri.port )
    close( site )
  end

  def keep( sess )
    addCachedSession( sess )
  end

private
  def open( dest, proxy = nil )
    sess = nil
    if ( cached = getCachedSession( dest ))
      sess = cached
    else
      sess = Session.new( dest, @agentName, @from )
      sess.proxy = proxy
      sess.requestedVersion = @protocolVersion if @protocolVersion
      sess.connectTimeout = @connectTimeout
      sess.connectRetry = @connectRetry
      sess.sendTimeout = @sendTimeout
      sess.receiveTimeout = @receiveTimeout
      sess.readBlockSize = @readBlockSize
      sess.debugDev = @debugDev
      sess.chunkSize = @chunkSize
    end
    sess
  end

  def close( dest )
    if ( cached = getCachedSession( dest ))
      cached.close
      true
    else
      false
    end
  end

  def getCachedSession( dest )
    cached = nil
    @sessPoolMutex.synchronize do
      newPool = []
      @sessPool.each do | s |
	if s.dest == dest
	  cached = s
	else
	  newPool << s
	end
      end
      @sessPool = newPool
    end
    cached
  end

  def addCachedSession( sess )
    @sessPoolMutex.synchronize do
      @sessPool << sess
    end
  end
end

###
## HTTPAccess2::DebugSocket -- debugging support
#
class DebugSocket
public
  attr_accessor :debugDev     # Device for dumping log for debugging.

  def initialize( host, port, debugDev )
    @debugDev = debugDev
    @socket = TCPSocket.new( host, port )
    @debugDev << '! CONNECTION ESTABLISHED' << "\n"
  end

  def addr
    @socket.addr
  end

  def close
    @debugDev << '! CONNECTION CLOSED' << "\n"
    @socket.close
  end

  def closed?
    @socket.closed?
  end

  def eof?
    @socket.eof?
  end

  def gets( *args )
    str = @socket.gets( *args )
    @debugDev << str
    str
  end

  def read( *args )
    str = @socket.read( *args )
    @debugDev << str
    str
  end

  def <<( str )
    dump( str )
  end

private
  def dump( str )
    @socket << str
    @debugDev << str
  end
end


###
## HTTPAccess2::Session -- manage http session with one site.
##   One ore more TCP sessions with the site may be created.
#
class Session	# :nodoc:

  class Error < StandardError	# :nodoc:
  end

  class InvalidState < Error	# :nodoc:
  end

  class BadResponse < Error	# :nodoc:
  end

  class KeepAliveDisconnected < Error	# :nodoc:
  end

  attr_reader :dest			# Destination site
  attr_reader :src			# Source site
  attr_accessor :proxy			# Proxy site

  attr_accessor :requestedVersion	# Requested protocol version

  attr_accessor :chunkSize		# Chunk size for chunked request
  attr_accessor :debugDev		# Device for dumping log for debugging

  # Those session parameters are not used now...
  attr_accessor :connectTimeout
  attr_accessor :connectRetry
  attr_accessor :sendTimeout
  attr_accessor :receiveTimeout
  attr_accessor :readBlockSize

  def initialize( dest, user_agent, from )
    @dest = dest
    @src = Site.new
    @proxy = nil
    @requestedVersion = VERSION

    @chunkSize = 102400
    @debugDev = nil

    @connectTimeout = nil
    @connectRetry = 1
    @sendTimeout = nil
    @receiveTimeout = nil
    @readBlockSize = nil

    @user_agent = user_agent
    @from = from
    @state = :INIT

    @requests = []

    @status = nil
    @reason = nil
    @headers = []
  end

  # Send a request to the server
  def query( req )
    connect() if @state == :INIT

    begin
      timeout( @sendTimeout ) do
	setHeaders( req )
	req.dump( @socket )
      end
    rescue TimeoutError
      close
      raise
    end

    @state = :META if @state == :WAIT
    @next_connection = nil
    @requests.push( req )
  end

  def close
    unless @socket.nil?
      @socket.close unless @socket.closed?
    end
    @state = :INIT
  end

  def closed?
    @state == :INIT
  end

  def getStatus
    version = status = reason = nil
    begin
      if @state != :META
	raise RuntimeError.new( "getStatus must be called at the beginning of a session." )
      end
      version, status, reason = readHeaders()
    rescue
      close
      raise
    end
    return version, status, reason
  end

  def getHeaders( &block )
    begin
      readHeaders() if @state == :META
    rescue
      close
      raise
    end
    if block
      @headers.each do | line |
	block.call( line )
      end
    else
      @headers
    end
  end

  def eof?
    if @content_length == 0
      true
    elsif @readbuf.length > 0
      false
    else
      @socket.closed? or @socket.eof?
    end
  end

  def getData( &block )
    begin
      readHeaders() if @state == :META
      return nil if @state != :DATA
      unless @state == :DATA
	raise InvalidState.new( 'state != DATA' )
      end
      data = nil
      if block
	until eof?
	  begin
	    timeout( @receiveTimeout ) do
	      data = readBody()
	    end
	  rescue TimeoutError
	    raise
	  end
	  block.call( data ) if data
	end
	data = nil	# Calling with block returns nil.
      else
	begin
	  timeout( @receiveTimeout ) do
	    data = readBody()
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
  LibNames = "( #{ RCS_FILE }/#{ RCS_REVISION }, #{ RUBY_VERSION_STRING } )"

  def setHeaders( req )
    if @user_agent
      req.header.set( 'User-Agent', "#{ @user_agent } #{ LibNames }" )
    end
    if @from
      req.header.set( 'From', @from )
    end
    req.header.set( 'Date', Time.now )
  end

  # Connect to the server
  def connect
    site = @proxy || @dest
    begin
      retryNumber = 0
      timeout( @connectTimeout ) do
	@socket = if @debugDev	
	    DebugSocket.new( site.host, site.port, @debugDev )
	  else
	    TCPSocket.new( site.host, site.port )
	  end
      end
    rescue TimeoutError
      if @connectRetry == 0
	retry
      else
	retryNumber += 1
	retry if retryNumber < @connectRetry
      end
      close
      raise
    end

    @src.host = @socket.addr[ 3 ]
    @src.port = @socket.addr[ 1 ]
    @state = :WAIT
    @readbuf = ''
  end

  # Read status block.
  StatusParseRegexp = %r(\AHTTP/(\d+\.\d+)\s+(\d+)(?:\s+(.*))?#{ RS }\z)
  def readHeaders
    if @state == :DATA
      get_data {}
      check_state()
    end
    unless @state == :META
      raise InvalidState, 'state != :META'
    end

    begin
      timeout( @receiveTimeout ) do
	begin
	  @status_line = @socket.gets( RS )
	  if @status_line.nil?
	    raise KeepAliveDisconnected.new
	  end
	  StatusParseRegexp =~ @status_line
	  unless $1
	    raise BadResponse.new( @status_line )
	  end
	  @version, @status, @reason = $1, $2.to_i, $3
	  @next_connection = if keepAliveEnabled?( @version )
	      true
	    else
	      false
	    end

	  @headers = []
	  until (( line = @socket.gets( RS )) == RS )
	    unless line
	      raise BadResponse.new( 'Unexpected EOF.' )
	    end
	    line.sub!( /#{ RS }\z/, '' )
	    if line.sub!( /^\t/, '' )
      	      @headers[-1] << line
	    else
      	      @headers.push( line )
      	    end
	  end
	end while ( @version == '1.1' && @status == 100 )
      end
    rescue TimeoutError
      raise
    end

    @content_length = nil
    @chunked = false
    @headers.each do | line |
      case line
      when /^Content-Length:\s+(\d+)/i
	@content_length = $1.to_i
      when /^Transfer-Encoding:\s+chunked/i
	@chunked = true
	@content_length = true  # how?
	@chunk_length = 0
      when /^Connection:\s+([-\w]+)/i, /^Proxy-Connection:\s+([-\w]+)/i
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

    if req.header.requestMethod == 'HEAD'
      @content_length = 0
      if @next_connection
        @state = :WAIT 
      else
        close
      end
    end

    @next_connection = false unless @content_length

    return [ @version, @status, @reason ]
  end

  def readBody
    if @chunked
      return readBodyChunked()
    elsif @content_length == 0
      return nil
    elsif @content_length
      return readBodyLength()
    else
      if @readbuf.length > 0
	data = @readbuf
	@readbuf = ''
	return data
      else
	data = @socket.read( @readBlockSize )
	data = nil if data.empty?	# Absorbing interface mismatch.
	return data
      end
    end
  end

  def readBodyLength
    maxbytes = @readBlockSize
    if @readbuf.length > 0
      data = @readbuf[0, @content_length]
      @readbuf[0, @content_length] = ''
      @content_length -= data.length
      return data
    end
    maxbytes = @content_length if maxbytes > @content_length
    data = @socket.read( maxbytes )
    if data
      @content_length -= data.length
    else
      @content_length = 0
    end
    return data
  end

  def readBodyChunked
    if @chunk_length == 0
      until ( i = @readbuf.index( RS ))
	@readbuf << @socket.gets( RS )
      end
      i += 2
      if @readbuf[0, i] == "0" << RS
	@content_length = 0
	unless ( @readbuf[0, 5] == "0" << RS << RS )
	  @readbuf << @socket.gets( RS )
	end
	@readbuf[0, 5] = ''
	return nil
      end
      @chunk_length = @readbuf[0, i].hex
      @readbuf[0, i] = ''
    end
    while @readbuf.length < @chunk_length + 2
      @readbuf << @socket.read( @chunk_length + 2 - @readbuf.length )
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

  ProtocolVersionRegexp = Regexp.new( '^(\d+)\.(\d+)$' )

  # Persistent connection is usable in 1.1 or later.
  def keepAliveEnabled?( version )
    ProtocolVersionRegexp =~ version
    bEnabled = if ( $1 && ( $1.to_i > 1 ))
	true
      elsif ( $2 && ( $2.to_i >= 1 ))
	true
      else
	false
      end
    return bEnabled
  end
end


end


HTTPClient = HTTPAccess2::Client
