require 'uri'
require 'httpclient'

class DAV
  attr_reader :headers

  def initialize(uri = nil)
    @uri = nil
    @headers = {}
    open(uri) if uri
    proxy = ENV['HTTP_PROXY'] || ENV['http_proxy'] || nil
    @client = HTTPClient.new(proxy)
  end

  def out
    STDOUT
  end

  def open(uri)
    @uri = if uri.is_a?(URI)
	uri
      else
	URI.parse(uri)
      end
  end

  def set_basic_auth(user_id, passwd)
    @client.set_basic_auth(@uri, user_id, passwd)
  end

  def get(target, local = nil)
    local ||= target
    target_uri = @uri + target
    if FileTest.exist?(local)
      raise RuntimeError.new("File #{ local } exists.")
    end
    f = File.open(local, "wb")
    res = @client.get(target_uri, nil, @headers) do |data|
      f << data
    end
    f.close
    out.puts("#{ res.header['content-length'][0] } bytes saved to file #{ target }.")
  end

  def put(local, target = nil)
    target ||= local
    target_uri = @uri + target
    out.puts("Sending file #{ local }.")
    res = @client.put(target_uri, File.open(local, "rb"), @headers)
    out.puts res.content.read
  end
end
