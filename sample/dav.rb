require 'uri'
require 'http-access2'

class DAV
  attr_reader :headers

  def initialize( uri = nil )
    @uri = nil
    @headers = {}
    open( uri ) if uri
    proxy = ENV[ 'HTTP_PROXY' ] || ENV[ 'http_proxy' ] || nil
    @client = HTTPAccess2::Client.new( proxy )
  end

  def out
    STDOUT
  end

  def open( uri )
    @uri = if uri.is_a?( URI )
	uri
      else
	URI.parse( uri )
      end
  end

  def setBasicAuth( userId, passwd )
    @client.setBasicAuth( @uri, userId, passwd )
  end

  def get( target, local = nil )
    local ||= target
    targetUri = @uri + target
    if FileTest.exist?( local )
      raise RuntimeError.new( "File #{ local } exists." )
    end
    f = File.open( local, "wb" )
    res = @client.get( targetUri, nil, @headers ) do | data |
      f << data
    end
    f.close
    out.puts( "#{ res.header[ 'content-length' ][ 0 ] } bytes saved to file #{ target }." )
  end

  def put( local, target = nil )
    target ||= local
    targetUri = @uri + target
    out.puts( "Sending file #{ local }." )
    res = @client.put( targetUri, File.open( local, "rb" ), @headers )
    out.puts res.content.read
  end
end
