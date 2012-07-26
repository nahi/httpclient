# -*- encoding: utf-8 -*-
require File.expand_path('helper', File.dirname(__FILE__))


class TestHTTPClient < Test::Unit::TestCase
  include Helper

  def setup
    super
    setup_server
    setup_client
  end

  def teardown
    super
  end

  def test_initialize
    setup_proxyserver
    escape_noproxy do
      @proxyio.string = ""
      @client = HTTPClient.new(proxyurl)
      assert_equal(URI.parse(proxyurl), @client.proxy)
      assert_equal(200, @client.head(serverurl).status)
      assert(/accept/ =~ @proxyio.string)
    end
  end

  def test_agent_name
    @client = HTTPClient.new(nil, "agent_name_foo")
    str = ""
    @client.debug_dev = str
    @client.get(serverurl)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_match(/^User-Agent: agent_name_foo \(#{HTTPClient::VERSION}/, lines[4])
  end

  def test_from
    @client = HTTPClient.new(nil, nil, "from_bar")
    str = ""
    @client.debug_dev = str
    @client.get(serverurl)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_match(/^From: from_bar/, lines[4])
  end

  def test_debug_dev
    str = ""
    @client.debug_dev = str
    assert_equal(str.object_id, @client.debug_dev.object_id)
    assert(str.empty?)
    @client.get(serverurl)
    assert(!str.empty?)
  end

  def test_debug_dev_stream
    str = ""
    @client.debug_dev = str
    conn = @client.get_async(serverurl)
    Thread.pass while !conn.finished?
    assert(!str.empty?)
  end

  def test_protocol_version_http09
    @client.protocol_version = 'HTTP/0.9'
    @client.debug_dev = str = ''
    @client.test_loopback_http_response << "hello\nworld\n"
    res = @client.get(serverurl + 'hello')
    assert_equal('0.9', res.http_version)
    assert_equal(nil, res.status)
    assert_equal(nil, res.reason)
    assert_equal("hello\nworld\n", res.content)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[2])
    assert_equal("GET /hello HTTP/0.9", lines[3])
    assert_equal("Connection: close", lines[6])
    assert_equal("= Response", lines[7])
    assert_match(/^hello$/, lines[8])
    assert_match(/^world$/, lines[9])
  end

  def test_protocol_version_http10
    assert_equal(nil, @client.protocol_version)
    @client.protocol_version = 'HTTP/1.0'
    assert_equal('HTTP/1.0', @client.protocol_version)
    str = ""
    @client.debug_dev = str
    @client.get(serverurl + 'hello')
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[2])
    assert_equal("GET /hello HTTP/1.0", lines[3])
    assert_equal("Connection: close", lines[6])
    assert_equal("= Response", lines[7])
  end

  def test_header_accept_by_default
    str = ""
    @client.debug_dev = str
    @client.get(serverurl)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("Accept: */*", lines[4])
  end

  def test_header_accept
    str = ""
    @client.debug_dev = str
    @client.get(serverurl, :header => {:Accept => 'text/html'})
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("Accept: text/html", lines[4])
  end

  def test_host_given
    str = ""
    @client.debug_dev = str
    @client.get(serverurl)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[2])
    assert_equal("GET / HTTP/1.1", lines[3])
    assert_equal("Host: localhost:#{serverport}", lines[6])
    #
    @client.reset_all
    str = ""
    @client.debug_dev = str
    @client.get(serverurl, nil, {'Host' => 'foo'})
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[2])
    assert_equal("GET / HTTP/1.1", lines[3])
    assert_equal("Host: foo", lines[4]) # use given param
  end

  def test_protocol_version_http11
    assert_equal(nil, @client.protocol_version)
    str = ""
    @client.debug_dev = str
    @client.get(serverurl)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[2])
    assert_equal("GET / HTTP/1.1", lines[3])
    assert_equal("Host: localhost:#{serverport}", lines[6])
    @client.protocol_version = 'HTTP/1.1'
    assert_equal('HTTP/1.1', @client.protocol_version)
    str = ""
    @client.debug_dev = str
    @client.get(serverurl)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[2])
    assert_equal("GET / HTTP/1.1", lines[3])
    @client.protocol_version = 'HTTP/1.0'
    str = ""
    @client.debug_dev = str
    @client.get(serverurl)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[2])
    assert_equal("GET / HTTP/1.0", lines[3])
  end

  def test_proxy
    setup_proxyserver
    escape_noproxy do
      assert_raises(URI::InvalidURIError) do
       	@client.proxy = "http://"
      end
      @client.proxy = ""
      assert_nil(@client.proxy)
      @client.proxy = "http://admin:admin@foo:1234"
      assert_equal(URI.parse("http://admin:admin@foo:1234"), @client.proxy)
      uri = URI.parse("http://bar:2345")
      @client.proxy = uri
      assert_equal(uri, @client.proxy)
      #
      @proxyio.string = ""
      @client.proxy = nil
      assert_equal(200, @client.head(serverurl).status)
      assert(/accept/ !~ @proxyio.string)
      #
      @proxyio.string = ""
      @client.proxy = proxyurl
      @client.debug_dev = str = ""
      assert_equal(200, @client.head(serverurl).status)
      assert(/accept/ =~ @proxyio.string)
      assert(/Host: localhost:#{serverport}/ =~ str)
    end
  end

  def test_host_header
    @client.proxy = proxyurl
    @client.debug_dev = str = ""
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\r\n\r\n"
    assert_equal(200, @client.head('http://www.example.com/foo').status)
    # ensure no ':80' is added.  some servers dislike that.
    assert(/\r\nHost: www\.example\.com\r\n/ =~ str)
    #
    @client.debug_dev = str = ""
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\r\n\r\n"
    assert_equal(200, @client.head('http://www.example.com:12345/foo').status)
    # ensure ':12345' exists.
    assert(/\r\nHost: www\.example\.com:12345\r\n/ =~ str)
  end

  def test_proxy_env
    setup_proxyserver
    escape_env do
      ENV['http_proxy'] = "http://admin:admin@foo:1234"
      ENV['NO_PROXY'] = "foobar"
      client = HTTPClient.new
      assert_equal(URI.parse("http://admin:admin@foo:1234"), client.proxy)
      assert_equal('foobar', client.no_proxy)
    end
  end

  def test_proxy_env_cgi
    setup_proxyserver
    escape_env do
      ENV['REQUEST_METHOD'] = 'GET' # CGI environment emulation
      ENV['http_proxy'] = "http://admin:admin@foo:1234"
      ENV['no_proxy'] = "foobar"
      client = HTTPClient.new
      assert_equal(nil, client.proxy)
      ENV['CGI_HTTP_PROXY'] = "http://admin:admin@foo:1234"
      client = HTTPClient.new
      assert_equal(URI.parse("http://admin:admin@foo:1234"), client.proxy)
    end
  end

  def test_empty_proxy_env
    setup_proxyserver
    escape_env do
      ENV['http_proxy'] = ""
      client = HTTPClient.new
      assert_equal(nil, client.proxy)
    end
  end

  def test_noproxy_for_localhost
    @proxyio.string = ""
    @client.proxy = proxyurl
    assert_equal(200, @client.head(serverurl).status)
    assert(/accept/ !~ @proxyio.string)
  end

  def test_no_proxy
    setup_proxyserver
    escape_noproxy do
      # proxy is not set.
      assert_equal(nil, @client.no_proxy)
      @client.no_proxy = 'localhost'
      assert_equal('localhost', @client.no_proxy)
      @proxyio.string = ""
      @client.proxy = nil
      assert_equal(200, @client.head(serverurl).status)
      assert(/accept/ !~ @proxyio.string)
      #
      @proxyio.string = ""
      @client.proxy = proxyurl
      assert_equal(200, @client.head(serverurl).status)
      assert(/accept/ !~ @proxyio.string)
      #
      @client.no_proxy = 'foobar'
      @proxyio.string = ""
      @client.proxy = proxyurl
      assert_equal(200, @client.head(serverurl).status)
      assert(/accept/ =~ @proxyio.string)
      #
      @client.no_proxy = 'foobar,localhost:baz'
      @proxyio.string = ""
      @client.proxy = proxyurl
      assert_equal(200, @client.head(serverurl).status)
      assert(/accept/ !~ @proxyio.string)
      #
      @client.no_proxy = 'foobar,localhost:443'
      @proxyio.string = ""
      @client.proxy = proxyurl
      assert_equal(200, @client.head(serverurl).status)
      assert(/accept/ =~ @proxyio.string)
      #
      @client.no_proxy = "foobar,localhost:443:localhost:#{serverport},baz"
      @proxyio.string = ""
      @client.proxy = proxyurl
      assert_equal(200, @client.head(serverurl).status)
      assert(/accept/ !~ @proxyio.string)
    end
  end

  def test_cookie_update_while_authentication
    escape_noproxy do
      @client.test_loopback_http_response << <<EOS
HTTP/1.0 401\r
Date: Fri, 19 Dec 2008 11:57:29 GMT\r
Content-Type: text/plain\r
Content-Length: 0\r
WWW-Authenticate: Basic realm="hello"\r
Set-Cookie: foo=bar; path=/; domain=.example.org; expires=#{Time.at(1924873200).httpdate}\r
\r
EOS
      @client.test_loopback_http_response << <<EOS
HTTP/1.1 200 OK\r
Content-Length: 5\r
Connection: close\r
\r
hello
EOS
      @client.debug_dev = str = ''
      @client.set_auth("http://www.example.org/baz/", 'admin', 'admin')
      assert_equal('hello', @client.get('http://www.example.org/baz/foo').content)
      assert_match(/^Cookie: foo=bar/, str)
      assert_match(/^Authorization: Basic YWRtaW46YWRtaW4=/, str)
    end
  end


  def test_proxy_ssl
    escape_noproxy do
      @client.proxy = 'http://admin:admin@localhost:8080/'
      # disconnected at initial 'CONNECT' so there're 2 loopback responses
      @client.test_loopback_http_response << <<EOS
HTTP/1.0 407 Proxy Authentication Required\r
Date: Fri, 19 Dec 2008 11:57:29 GMT\r
Content-Type: text/plain\r
Content-Length: 0\r
Proxy-Authenticate: Basic realm="hello"\r
Proxy-Connection: close\r
\r
EOS
      @client.test_loopback_http_response << <<EOS
HTTP/1.0 200 Connection established\r
\r
HTTP/1.1 200 OK\r
Content-Length: 5\r
Connection: close\r
\r
hello
EOS
      assert_equal('hello', @client.get('https://localhost:17171/baz').content)
    end
  end

  def test_loopback_response
    @client.test_loopback_response << 'message body 1'
    @client.test_loopback_response << 'message body 2'
    assert_equal('message body 1', @client.get_content('http://somewhere'))
    assert_equal('message body 2', @client.get_content('http://somewhere'))
    #
    @client.debug_dev = str = ''
    @client.test_loopback_response << 'message body 3'
    assert_equal('message body 3', @client.get_content('http://somewhere'))
    assert_match(/message body 3/, str)
  end

  def test_loopback_response_stream
    @client.test_loopback_response << 'message body 1'
    @client.test_loopback_response << 'message body 2'
    conn = @client.get_async('http://somewhere')
    Thread.pass while !conn.finished?
    assert_equal('message body 1', conn.pop.content.read)
    conn = @client.get_async('http://somewhere')
    Thread.pass while !conn.finished?
    assert_equal('message body 2', conn.pop.content.read)
  end

  def test_loopback_http_response
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\ncontent-length: 100\n\nmessage body 1"
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\ncontent-length: 100\n\nmessage body 2"
    assert_equal('message body 1', @client.get_content('http://somewhere'))
    assert_equal('message body 2', @client.get_content('http://somewhere'))
  end

  def test_multiline_header
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\nX-Foo: XXX\n   YYY\nX-Bar: \n XXX\n\tYYY\ncontent-length: 100\n\nmessage body 1"
    res = @client.get('http://somewhere')
    assert_equal('message body 1', res.content)
    assert_equal(['XXX YYY'], res.header['x-foo'])
    assert_equal(['XXX YYY'], res.header['x-bar'])
  end

  def test_broken_header
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\nXXXXX\ncontent-length: 100\n\nmessage body 1"
    res = @client.get('http://somewhere')
    assert_equal('message body 1', res.content)
  end

  def test_redirect_non_https
    url = serverurl + 'redirect1'
    https_url = URI.parse(url)
    https_url.scheme = 'https'
    #
    redirect_to_http = "HTTP/1.0 302 OK\nLocation: #{url}\n\n"
    redirect_to_https = "HTTP/1.0 302 OK\nLocation: #{https_url}\n\n"
    #
    # https -> http is denied
    @client.test_loopback_http_response << redirect_to_http
    assert_raises(HTTPClient::BadResponseError) do
      @client.get_content(https_url)
    end
    #
    # http -> http is OK
    @client.reset_all
    @client.test_loopback_http_response << redirect_to_http
    assert_equal('hello', @client.get_content(url))
    #
    # http -> https is OK
    @client.reset_all
    @client.test_loopback_http_response << redirect_to_https
    assert_raises(OpenSSL::SSL::SSLError) do
      # trying to normal endpoint with SSL -> SSL negotiation failure
      @client.get_content(url)
    end
    #
    # https -> https is OK
    @client.reset_all
    @client.test_loopback_http_response << redirect_to_https
    assert_raises(OpenSSL::SSL::SSLError) do
      # trying to normal endpoint with SSL -> SSL negotiation failure
      @client.get_content(https_url)
    end
    #
    # https -> http with strict_redirect_uri_callback
    @client.redirect_uri_callback = @client.method(:strict_redirect_uri_callback)
    @client.test_loopback_http_response << redirect_to_http
    assert_raises(HTTPClient::BadResponseError) do
      @client.get_content(https_url)
    end
  end

  def test_redirect_relative
    @client.test_loopback_http_response << "HTTP/1.0 302 OK\nLocation: hello\n\n"
    silent do
      assert_equal('hello', @client.get_content(serverurl + 'redirect1'))
    end
    #
    @client.reset_all
    @client.redirect_uri_callback = @client.method(:strict_redirect_uri_callback)
    assert_equal('hello', @client.get_content(serverurl + 'redirect1'))
    @client.reset_all
    @client.test_loopback_http_response << "HTTP/1.0 302 OK\nLocation: hello\n\n"
    begin
      @client.get_content(serverurl + 'redirect1')
      assert(false)
    rescue HTTPClient::BadResponseError => e
      assert_equal(302, e.res.status)
    end
  end

  def test_redirect_https_relative
    url = serverurl + 'redirect1'
    https_url = URI.parse(url)
    https_url.scheme = 'https'
    @client.test_loopback_http_response << "HTTP/1.0 302 OK\nLocation: /foo\n\n"
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\n\nhello"
    silent do
      assert_equal('hello', @client.get_content(https_url))
    end
  end

  def test_no_content
    assert_nothing_raised do
      timeout(2) do
        @client.get(serverurl + 'status', :status => 101)
        @client.get(serverurl + 'status', :status => 204)
        @client.get(serverurl + 'status', :status => 304)
      end
    end
  end

  def test_get_content
    assert_equal('hello', @client.get_content(serverurl + 'hello'))
    assert_equal('hello', @client.get_content(serverurl + 'redirect1'))
    assert_equal('hello', @client.get_content(serverurl + 'redirect2'))
    url = serverurl.sub(/localhost/, '127.0.0.1')
    assert_equal('hello', @client.get_content(url + 'hello'))
    assert_equal('hello', @client.get_content(url + 'redirect1'))
    assert_equal('hello', @client.get_content(url + 'redirect2'))
    @client.reset(serverurl)
    @client.reset(url)
    @client.reset(serverurl)
    @client.reset(url)
    assert_raises(HTTPClient::BadResponseError) do
      @client.get_content(serverurl + 'notfound')
    end
    assert_raises(HTTPClient::BadResponseError) do
      @client.get_content(serverurl + 'redirect_self')
    end
    called = false
    @client.redirect_uri_callback = lambda { |uri, res|
      newuri = res.header['location'][0]
      called = true
      newuri
    }
    assert_equal('hello', @client.get_content(serverurl + 'relative_redirect'))
    assert(called)
  end

  GZIP_CONTENT = "\x1f\x8b\x08\x00\x1a\x96\xe0\x4c\x00\x03\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00"
  DEFLATE_CONTENT = "\x78\x9c\xcb\x48\xcd\xc9\xc9\x07\x00\x06\x2c\x02\x15"
  GZIP_CONTENT.force_encoding('BINARY') if GZIP_CONTENT.respond_to?(:force_encoding)
  DEFLATE_CONTENT.force_encoding('BINARY') if DEFLATE_CONTENT.respond_to?(:force_encoding)
  def test_get_gzipped_content
    @client.transparent_gzip_decompression = false
    content = @client.get_content(serverurl + 'compressed?enc=gzip')
    assert_not_equal('hello', content)
    assert_equal(GZIP_CONTENT, content)
    @client.transparent_gzip_decompression = true
    assert_equal('hello', @client.get_content(serverurl + 'compressed?enc=gzip'))
    assert_equal('hello', @client.get_content(serverurl + 'compressed?enc=deflate'))
    @client.transparent_gzip_decompression = false
  end

  def test_get_content_with_block
    @client.get_content(serverurl + 'hello') do |str|
      assert_equal('hello', str)
    end
    @client.get_content(serverurl + 'redirect1') do |str|
      assert_equal('hello', str)
    end
    @client.get_content(serverurl + 'redirect2') do |str|
      assert_equal('hello', str)
    end
  end

  def test_post_content
    assert_equal('hello', @client.post_content(serverurl + 'hello'))
    assert_equal('hello', @client.post_content(serverurl + 'redirect1'))
    assert_equal('hello', @client.post_content(serverurl + 'redirect2'))
    assert_raises(HTTPClient::BadResponseError) do
      @client.post_content(serverurl + 'notfound')
    end
    assert_raises(HTTPClient::BadResponseError) do
      @client.post_content(serverurl + 'redirect_self')
    end
    called = false
    @client.redirect_uri_callback = lambda { |uri, res|
      newuri = res.header['location'][0]
      called = true
      newuri
    }
    assert_equal('hello', @client.post_content(serverurl + 'relative_redirect'))
    assert(called)
  end

  def test_post_content_io
    post_body = StringIO.new("1234567890")
    assert_equal('post,1234567890', @client.post_content(serverurl + 'servlet', post_body))
    post_body = StringIO.new("1234567890")
    assert_equal('post,1234567890', @client.post_content(serverurl + 'servlet_redirect', post_body))
    #
    post_body = StringIO.new("1234567890")
    post_body.read(5)
    assert_equal('post,67890', @client.post_content(serverurl + 'servlet_redirect', post_body))
  end

  def test_head
    assert_equal("head", @client.head(serverurl + 'servlet').header["x-head"][0])
    param = {'1'=>'2', '3'=>'4'}
    res = @client.head(serverurl + 'servlet', param)
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_head_async
    param = {'1'=>'2', '3'=>'4'}
    conn = @client.head_async(serverurl + 'servlet', param)
    Thread.pass while !conn.finished?
    res = conn.pop
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_get
    assert_equal("get", @client.get(serverurl + 'servlet').content)
    param = {'1'=>'2', '3'=>'4'}
    res = @client.get(serverurl + 'servlet', param)
    assert_equal(param, params(res.header["x-query"][0]))
    assert_nil(res.contenttype)
    #
    url = serverurl.to_s + 'servlet?5=6&7=8'
    res = @client.get(url, param)
    assert_equal(param.merge("5"=>"6", "7"=>"8"), params(res.header["x-query"][0]))
    assert_nil(res.contenttype)
  end

  def test_get_follow_redirect
    assert_equal('hello', @client.get(serverurl + 'hello', :follow_redirect => true).body)
    assert_equal('hello', @client.get(serverurl + 'redirect1', :follow_redirect => true).body)
    assert_equal('hello', @client.get(serverurl + 'redirect2', :follow_redirect => true).body)
  end

  def test_get_async
    param = {'1'=>'2', '3'=>'4'}
    conn = @client.get_async(serverurl + 'servlet', param)
    Thread.pass while !conn.finished?
    res = conn.pop
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_get_async_for_largebody
    conn = @client.get_async(serverurl + 'largebody')
    res = conn.pop
    assert_equal(1000*1000, res.content.read.length)
  end

  def test_get_with_block
    called = false
    res = @client.get(serverurl + 'servlet') { |str|
      assert_equal('get', str)
      called = true
    }
    assert(called)
    # res does not have a content
    assert_nil(res.content)
  end

  def test_get_with_block_chunk_string_recycle
    @client.read_block_size = 2
    body = []
    res = @client.get(serverurl + 'servlet') { |str|
      body << str
    }
    assert_equal(2, body.size)
    assert_equal("get", body.join) # Was "tt" by String object recycle...
  end

  def test_post
    assert_equal("post", @client.post(serverurl + 'servlet').content[0, 4])
    param = {'1'=>'2', '3'=>'4'}
    res = @client.post(serverurl + 'servlet', param)
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_post_follow_redirect
    assert_equal('hello', @client.post(serverurl + 'hello', :follow_redirect => true).body)
    assert_equal('hello', @client.post(serverurl + 'redirect1', :follow_redirect => true).body)
    assert_equal('hello', @client.post(serverurl + 'redirect2', :follow_redirect => true).body)
  end

  def test_post_with_content_type
    param = [['1', '2'], ['3', '4']]
    ext = {'content-type' => 'application/x-www-form-urlencoded', 'hello' => 'world'}
    assert_equal("post", @client.post(serverurl + 'servlet').content[0, 4], ext)
    res = @client.post(serverurl + 'servlet', param, ext)
    assert_equal(Hash[param], params(res.header["x-query"][0]))
    #
    ext = [['content-type', 'multipart/form-data'], ['hello', 'world']]
    assert_equal("post", @client.post(serverurl + 'servlet').content[0, 4], ext)
    res = @client.post(serverurl + 'servlet', param, ext)
    assert_match(/Content-Disposition: form-data; name="1"/, res.content)
    assert_match(/Content-Disposition: form-data; name="3"/, res.content)
    #
    ext = {'content-type' => 'multipart/form-data; boundary=hello'}
    assert_equal("post", @client.post(serverurl + 'servlet').content[0, 4], ext)
    res = @client.post(serverurl + 'servlet', param, ext)
    assert_match(/Content-Disposition: form-data; name="1"/, res.content)
    assert_match(/Content-Disposition: form-data; name="3"/, res.content)
    assert_equal("post,--hello\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n2\r\n--hello\r\nContent-Disposition: form-data; name=\"3\"\r\n\r\n4\r\n--hello--\r\n\r\n", res.content)
  end

  def test_post_with_file
    STDOUT.sync = true
    File.open(__FILE__) do |file|
      res = @client.post(serverurl + 'servlet', {1=>2, 3=>file})
      assert_match(/^Content-Disposition: form-data; name="1"\r\n/nm, res.content)
      assert_match(/^Content-Disposition: form-data; name="3";/, res.content)
      assert_match(/FIND_TAG_IN_THIS_FILE/, res.content)
    end
  end

  def test_post_with_file_without_size
    STDOUT.sync = true
    File.open(__FILE__) do |file|
      def file.size
        # Simulates some strange Windows behaviour
        raise SystemCallError.new "Unknown Error (20047)"
      end
      assert_nothing_raised do
        @client.post(serverurl + 'servlet', {1=>2, 3=>file})
      end
    end
  end

  def test_post_with_io # streaming, but not chunked
    myio = StringIO.new("X" * (HTTP::Message::Body::DEFAULT_CHUNK_SIZE + 1))
    def myio.read(*args)
      @called ||= 0
      @called += 1
      super
    end
    def myio.called
      @called
    end
    @client.debug_dev = str = StringIO.new
    res = @client.post(serverurl + 'servlet', {1=>2, 3=>myio})
    assert_match(/\r\nContent-Disposition: form-data; name="1"\r\n/m, res.content)
    assert_match(/\r\n2\r\n/m, res.content)
    assert_match(/\r\nContent-Disposition: form-data; name="3"; filename=""\r\n/m, res.content)
    assert_match(/\r\nContent-Length:/m, str.string)
    assert_equal(3, myio.called)
  end

  def test_post_with_io_nosize # streaming + chunked post
    myio = StringIO.new("4")
    def myio.size
      nil
    end
    @client.debug_dev = str = StringIO.new
    res = @client.post(serverurl + 'servlet', {1=>2, 3=>myio})
    assert_match(/\r\nContent-Disposition: form-data; name="1"\r\n/m, res.content)
    assert_match(/\r\n2\r\n/m, res.content)
    assert_match(/\r\nContent-Disposition: form-data; name="3"; filename=""\r\n/m, res.content)
    assert_match(/\r\n4\r\n/m, res.content)
    assert_match(/\r\nTransfer-Encoding: chunked\r\n/m, str.string)
  end

  def test_post_async
    param = {'1'=>'2', '3'=>'4'}
    conn = @client.post_async(serverurl + 'servlet', param)
    Thread.pass while !conn.finished?
    res = conn.pop
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_post_with_block
    called = false
    res = @client.post(serverurl + 'servlet') { |str|
      assert_equal('post,', str)
      called = true
    }
    assert(called)
    assert_nil(res.content)
    #
    called = false
    param = [['1', '2'], ['3', '4']]
    res = @client.post(serverurl + 'servlet', param) { |str|
      assert_equal('post,1=2&3=4', str)
      called = true
    }
    assert(called)
    assert_equal('1=2&3=4', res.header["x-query"][0])
    assert_nil(res.content)
  end

  def test_post_with_custom_multipart
    ext = {'content-type' => 'multipart/form-data'}
    assert_equal("post", @client.post(serverurl + 'servlet').content[0, 4], ext)
    body = [{ 'Content-Disposition' => 'form-data; name="1"', :content => "2"},
            { 'Content-Disposition' => 'form-data; name="3"', :content => "4"}]
    res = @client.post(serverurl + 'servlet', body, ext)
    assert_match(/Content-Disposition: form-data; name="1"/, res.content)
    assert_match(/Content-Disposition: form-data; name="3"/, res.content)
    #
    ext = {'content-type' => 'multipart/form-data; boundary=hello'}
    assert_equal("post", @client.post(serverurl + 'servlet').content[0, 4], ext)
    res = @client.post(serverurl + 'servlet', body, ext)
    assert_match(/Content-Disposition: form-data; name="1"/, res.content)
    assert_match(/Content-Disposition: form-data; name="3"/, res.content)
    assert_equal("post,--hello\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n2\r\n--hello\r\nContent-Disposition: form-data; name=\"3\"\r\n\r\n4\r\n--hello--\r\n\r\n", res.content)
  end

  def test_post_with_custom_multipart_and_file
    STDOUT.sync = true
    File.open(__FILE__) do |file|
      ext = { 'Content-Type' => 'multipart/alternative' }
      body = [{ 'Content-Type' => 'text/plain', :content => "this is only a test" },
              { 'Content-Type' => 'application/x-ruby', :content => file }]
      res = @client.post(serverurl + 'servlet', body, ext)
      assert_match(/^Content-Type: text\/plain\r\n/m, res.content)
      assert_match(/^this is only a test\r\n/m, res.content)
      assert_match(/^Content-Type: application\/x-ruby\r\n/m, res.content)
      assert_match(/FIND_TAG_IN_THIS_FILE/, res.content)
    end
  end

  def test_put
    assert_equal("put", @client.put(serverurl + 'servlet').content)
    param = {'1'=>'2', '3'=>'4'}
    res = @client.put(serverurl + 'servlet', param)
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_put_bytesize
    res = @client.put(serverurl + 'servlet', 'txt' => 'あいうえお')
    assert_equal('txt=%E3%81%82%E3%81%84%E3%81%86%E3%81%88%E3%81%8A', res.header["x-query"][0])
    assert_equal('15', res.header["x-size"][0])
  end

  def test_put_async
    param = {'1'=>'2', '3'=>'4'}
    conn = @client.put_async(serverurl + 'servlet', param)
    Thread.pass while !conn.finished?
    res = conn.pop
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_delete
    assert_equal("delete", @client.delete(serverurl + 'servlet').content)
  end

  def test_delete_async
    conn = @client.delete_async(serverurl + 'servlet')
    Thread.pass while !conn.finished?
    res = conn.pop
    assert_equal('delete', res.content.read)
  end

  def test_options
    assert_equal("options", @client.options(serverurl + 'servlet').content)
  end

  def test_options_async
    conn = @client.options_async(serverurl + 'servlet')
    Thread.pass while !conn.finished?
    res = conn.pop
    assert_equal('options', res.content.read)
  end

  def test_propfind
    assert_equal("propfind", @client.propfind(serverurl + 'servlet').content)
  end

  def test_propfind_async
    conn = @client.propfind_async(serverurl + 'servlet')
    Thread.pass while !conn.finished?
    res = conn.pop
    assert_equal('propfind', res.content.read)
  end

  def test_proppatch
    assert_equal("proppatch", @client.proppatch(serverurl + 'servlet').content)
    param = {'1'=>'2', '3'=>'4'}
    res = @client.proppatch(serverurl + 'servlet', param)
    assert_equal('proppatch', res.content)
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_proppatch_async
    param = {'1'=>'2', '3'=>'4'}
    conn = @client.proppatch_async(serverurl + 'servlet', param)
    Thread.pass while !conn.finished?
    res = conn.pop
    assert_equal('proppatch', res.content.read)
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_trace
    assert_equal("trace", @client.trace(serverurl + 'servlet').content)
    param = {'1'=>'2', '3'=>'4'}
    res = @client.trace(serverurl + 'servlet', param)
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_trace_async
    param = {'1'=>'2', '3'=>'4'}
    conn = @client.trace_async(serverurl + 'servlet', param)
    Thread.pass while !conn.finished?
    res = conn.pop
    assert_equal(param, params(res.header["x-query"][0]))
  end

  def test_chunked
    assert_equal('chunked', @client.get_content(serverurl + 'chunked', { 'msg' => 'chunked' }))
  end

  def test_chunked_empty
    assert_equal('', @client.get_content(serverurl + 'chunked', { 'msg' => '' }))
  end

  def test_get_query
    assert_equal({'1'=>'2'}, check_query_get({1=>2}))
    assert_equal({'a'=>'A', 'B'=>'b'}, check_query_get({"a"=>"A", "B"=>"b"}))
    assert_equal({'&'=>'&'}, check_query_get({"&"=>"&"}))
    assert_equal({'= '=>' =+'}, check_query_get({"= "=>" =+"}))
    assert_equal(
      ['=', '&'].sort,
      check_query_get([["=", "="], ["=", "&"]])['='].to_ary.sort
    )
    assert_equal({'123'=>'45'}, check_query_get('123=45'))
    assert_equal({'12 3'=>'45', ' '=>' '}, check_query_get('12+3=45&+=+'))
    assert_equal({}, check_query_get(''))
    assert_equal({'1'=>'2'}, check_query_get({1=>StringIO.new('2')}))
    assert_equal({'1'=>'2', '3'=>'4'}, check_query_get(StringIO.new('3=4&1=2')))
  end

  def test_post_body
    assert_equal({'1'=>'2'}, check_query_post({1=>2}))
    assert_equal({'a'=>'A', 'B'=>'b'}, check_query_post({"a"=>"A", "B"=>"b"}))
    assert_equal({'&'=>'&'}, check_query_post({"&"=>"&"}))
    assert_equal({'= '=>' =+'}, check_query_post({"= "=>" =+"}))
    assert_equal(
      ['=', '&'].sort,
      check_query_post([["=", "="], ["=", "&"]])['='].to_ary.sort
    )
    assert_equal({'123'=>'45'}, check_query_post('123=45'))
    assert_equal({'12 3'=>'45', ' '=>' '}, check_query_post('12+3=45&+=+'))
    assert_equal({}, check_query_post(''))
    #
    post_body = StringIO.new("foo=bar&foo=baz")
    assert_equal(
      ["bar", "baz"],
      check_query_post(post_body)["foo"].to_ary.sort
    )
  end

  def test_extra_headers
    str = ""
    @client.debug_dev = str
    @client.head(serverurl, nil, {"ABC" => "DEF"})
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_match("ABC: DEF", lines[4])
    #
    str = ""
    @client.debug_dev = str
    @client.get(serverurl, nil, [["ABC", "DEF"], ["ABC", "DEF"]])
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_match("ABC: DEF", lines[4])
    assert_match("ABC: DEF", lines[5])
  end

  def test_http_custom_date_header
    @client.debug_dev = (str = "")
    res = @client.get(serverurl + 'hello', :header => {'Date' => 'foo'})
    lines = str.split(/(?:\r?\n)+/)
    assert_equal('Date: foo', lines[4])
  end

  def test_timeout
    assert_equal(60, @client.connect_timeout)
    assert_equal(120, @client.send_timeout)
    assert_equal(60, @client.receive_timeout)
    #
    @client.connect_timeout = 1
    @client.send_timeout = 2
    @client.receive_timeout = 3
    assert_equal(1, @client.connect_timeout)
    assert_equal(2, @client.send_timeout)
    assert_equal(3, @client.receive_timeout)
  end

  def test_connect_timeout
    # ToDo
  end

  def test_send_timeout
    # ToDo
  end

  def test_receive_timeout
    # this test takes 2 sec
    assert_equal('hello', @client.get_content(serverurl + 'sleep?sec=2'))
    @client.receive_timeout = 1
    assert_equal('hello', @client.get_content(serverurl + 'sleep?sec=0'))
    assert_raise(HTTPClient::ReceiveTimeoutError) do
      @client.get_content(serverurl + 'sleep?sec=2')
    end
    @client.receive_timeout = 3
    assert_equal('hello', @client.get_content(serverurl + 'sleep?sec=2'))
  end

  def test_receive_timeout_post
    # this test takes 2 sec
    assert_equal('hello', @client.post(serverurl + 'sleep', :sec => 2).content)
    @client.receive_timeout = 1
    assert_equal('hello', @client.post(serverurl + 'sleep', :sec => 0).content)
    assert_raise(HTTPClient::ReceiveTimeoutError) do
      @client.post(serverurl + 'sleep', :sec => 2)
    end
    @client.receive_timeout = 3
    assert_equal('hello', @client.post(serverurl + 'sleep', :sec => 2).content)
  end

  def test_async_error
    assert_raise( SocketError ) do
      conn = @client.get_async("http://non-existing-host/")
      conn.pop
    end
  end

  def test_reset
    url = serverurl + 'servlet'
    assert_nothing_raised do
      5.times do
        @client.get(url)
        @client.reset(url)
      end
    end
  end

  def test_reset_all
    assert_nothing_raised do
      5.times do
        @client.get(serverurl + 'servlet')
        @client.reset_all
      end
    end
  end

  def test_cookies
    cookiefile = File.join(File.dirname(File.expand_path(__FILE__)), 'test_cookies_file')
    File.open(cookiefile, "wb") do |f|
      f << "http://rubyforge.org/account/login.php	session_ser	LjEwMy45Ni40Ni0q%2A-fa0537de8cc31	2000000000	.rubyforge.org	/	13\n"
    end
    @client.set_cookie_store(cookiefile)
    cookie = @client.cookie_manager.cookies.first
    url = cookie.url
    assert(cookie.domain_match(url.host, cookie.domain))
    #
    @client.reset_all
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\nSet-Cookie: foo=bar; expires=#{Time.at(1924873200).gmtime.httpdate}\n\nOK"
    @client.get_content('http://rubyforge.org/account/login.php')
    @client.save_cookie_store
    str = File.read(cookiefile)
    assert_match(%r(http://rubyforge.org/account/login.php	foo	bar	1924873200	rubyforge.org	/account	1), str)
    File.unlink(cookiefile)
  end

  def test_eof_error_length
    io = StringIO.new('')
    def io.gets(*arg)
      @buf ||= ["HTTP/1.0 200 OK\n", "content-length: 123\n", "\n"]
      @buf.shift
    end
    def io.readpartial(size, buf)
      @second ||= false
      if !@second
        @second = '1st'
        buf << "abc"
        buf
      elsif @second == '1st'
        @second = '2nd'
        raise EOFError.new
      else
        raise Exception.new
      end
    end
    def io.eof?
      true
    end
    @client.test_loopback_http_response << io
    assert_nothing_raised do
      @client.get('http://foo/bar')
    end
  end

  def test_eof_error_rest
    io = StringIO.new('')
    def io.gets(*arg)
      @buf ||= ["HTTP/1.0 200 OK\n", "\n"]
      @buf.shift
    end
    def io.readpartial(size, buf)
      @second ||= false
      if !@second
        @second = '1st'
        buf << "abc"
        buf
      elsif @second == '1st'
        @second = '2nd'
        raise EOFError.new
      else
        raise Exception.new
      end
    end
    def io.eof?
      true
    end
    @client.test_loopback_http_response << io
    assert_nothing_raised do
      @client.get('http://foo/bar')
    end
  end

  def test_urify
    extend HTTPClient::Util
    assert_nil(urify(nil))
    uri = 'http://foo'
    assert_equal(URI.parse(uri), urify(uri))
    assert_equal(URI.parse(uri), urify(URI.parse(uri)))
  end

  def test_connection
    c = HTTPClient::Connection.new
    assert(c.finished?)
    assert_nil(c.join)
  end

  def test_site
    site = HTTPClient::Site.new
    assert_equal('tcp', site.scheme)
    assert_equal('0.0.0.0', site.host)
    assert_equal(0, site.port)
    assert_equal('tcp://0.0.0.0:0', site.addr)
    assert_equal('tcp://0.0.0.0:0', site.to_s)
    assert_nothing_raised do
      site.inspect
    end
    #
    site = HTTPClient::Site.new(URI.parse('http://localhost:12345/foo'))
    assert_equal('http', site.scheme)
    assert_equal('localhost', site.host)
    assert_equal(12345, site.port)
    assert_equal('http://localhost:12345', site.addr)
    assert_equal('http://localhost:12345', site.to_s)
    assert_nothing_raised do
      site.inspect
    end
    #
    site1 = HTTPClient::Site.new(URI.parse('http://localhost:12341/'))
    site2 = HTTPClient::Site.new(URI.parse('http://localhost:12342/'))
    site3 = HTTPClient::Site.new(URI.parse('http://localhost:12342/'))
    assert(!(site1 == site2))
    h = { site1 => 'site1', site2 => 'site2' }
    h[site3] = 'site3'
    assert_equal('site1', h[site1])
    assert_equal('site3', h[site2])
  end

  def test_http_header
    res = @client.get(serverurl + 'hello')
    assert_equal('text/html', res.contenttype)
    assert_equal(5, res.header.get(nil).size)
    #
    res.header.delete('connection')
    assert_equal(4, res.header.get(nil).size)
    #
    res.header['foo'] = 'bar'
    assert_equal(['bar'], res.header['foo'])
    #
    assert_equal([['foo', 'bar']], res.header.get('foo'))
    res.header['foo'] = ['bar', 'bar2']
    assert_equal([['foo', 'bar'], ['foo', 'bar2']], res.header.get('foo'))
  end

  def test_mime_type
    assert_equal('text/plain', HTTP::Message.mime_type('foo.txt'))
    assert_equal('text/html', HTTP::Message.mime_type('foo.html'))
    assert_equal('text/html', HTTP::Message.mime_type('foo.htm'))
    assert_equal('application/msword', HTTP::Message.mime_type('foo.doc'))
    assert_equal('image/png', HTTP::Message.mime_type('foo.png'))
    assert_equal('image/gif', HTTP::Message.mime_type('foo.gif'))
    assert_equal('image/jpeg', HTTP::Message.mime_type('foo.jpg'))
    assert_equal('image/jpeg', HTTP::Message.mime_type('foo.jpeg'))
    assert_equal('application/octet-stream', HTTP::Message.mime_type('foo.unknown'))
    #
    handler = lambda { |path| 'hello/world' }
    assert_nil(HTTP::Message.mime_type_handler)
    assert_nil(HTTP::Message.get_mime_type_func)
    HTTP::Message.mime_type_handler = handler
    assert_not_nil(HTTP::Message.mime_type_handler)
    assert_not_nil(HTTP::Message.get_mime_type_func)
    assert_equal('hello/world', HTTP::Message.mime_type('foo.txt'))
    HTTP::Message.mime_type_handler = nil
    assert_equal('text/plain', HTTP::Message.mime_type('foo.txt'))
    HTTP::Message.set_mime_type_func(nil)
    assert_equal('text/plain', HTTP::Message.mime_type('foo.txt'))
    #
    handler = lambda { |path| nil }
    HTTP::Message.mime_type_handler = handler
    assert_equal('application/octet-stream', HTTP::Message.mime_type('foo.txt'))
  end

  def test_connect_request
    req = HTTP::Message.new_connect_request(URI.parse('https://foo/bar'))
    assert_equal("CONNECT foo:443 HTTP/1.0\r\n\r\n", req.dump)
    req = HTTP::Message.new_connect_request(URI.parse('https://example.com/'))
    assert_equal("CONNECT example.com:443 HTTP/1.0\r\n\r\n", req.dump)
  end

  def test_response
    res = HTTP::Message.new_response('response')
    res.contenttype = 'text/plain'
    res.header.body_date = Time.at(946652400)
    assert_equal(
      [
        "",
        "Content-Length: 8",
        "Content-Type: text/plain",
        "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
        "Status: 200 OK",
        "response"
      ],
      res.dump.split(/\r\n/).sort
    )
    assert_equal(['8'], res.header['Content-Length'])
    assert_equal('8', res.headers['Content-Length'])
    res.header.set('foo', 'bar')
    assert_equal(
      [
        "",
        "Content-Length: 8",
        "Content-Type: text/plain",
        "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
        "Status: 200 OK",
        "foo: bar",
        "response"
      ],
      res.dump.split(/\r\n/).sort
    )
    # nil body
    res = HTTP::Message.new_response(nil)
    assert_equal(
      [
        "Content-Length: 0",
        "Content-Type: text/html; charset=us-ascii",
        "Status: 200 OK"
      ],
      res.dump.split(/\r\n/).sort
    )
    # for mod_ruby env
    Object.const_set('Apache', nil)
    begin
      res = HTTP::Message.new_response('response')
      assert(res.dump.split(/\r\n/).any? { |line| /^Date/ =~ line })
      #
      res = HTTP::Message.new_response('response')
      res.contenttype = 'text/plain'
      res.header.body_date = Time.at(946652400)
      res.header['Date'] = Time.at(946652400).httpdate
      assert_equal(
        [
          "",
          "Content-Length: 8",
          "Content-Type: text/plain",
          "Date: Fri, 31 Dec 1999 15:00:00 GMT",
          "HTTP/1.1 200 OK",
          "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
          "response"
        ],
        res.dump.split(/\r\n/).sort
      )
    ensure
      Object.instance_eval { remove_const('Apache') }
    end
  end

  def test_response_cookies
    res = HTTP::Message.new_response('response')
    res.contenttype = 'text/plain'
    res.header.body_date = Time.at(946652400)
    assert_nil(res.cookies)
    #
    res.header['Set-Cookie'] = [
      'CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT',
      'PART_NUMBER=ROCKET_LAUNCHER_0001; path=/'
    ]
    assert_equal(
      [
        "",
        "Content-Length: 8",
        "Content-Type: text/plain",
        "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
        "Set-Cookie: CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT",
        "Set-Cookie: PART_NUMBER=ROCKET_LAUNCHER_0001; path=/",
        "Status: 200 OK",
        "response"
      ],
      res.dump.split(/\r\n/).sort
    )
    assert_equal(2, res.cookies.size)
    assert_equal('CUSTOMER', res.cookies[0].name)
    assert_equal('PART_NUMBER', res.cookies[1].name)
  end

  if !defined?(JRUBY_VERSION) and RUBY_VERSION < '1.9'
    def test_timeout_scheduler
      assert_equal('hello', @client.get_content(serverurl + 'hello'))
      status =  HTTPClient.timeout_scheduler.instance_eval { @thread.kill; @thread.join; @thread.status }
      assert(!status) # dead
      assert_equal('hello', @client.get_content(serverurl + 'hello'))
    end
  end

  def test_session_manager
    mgr = HTTPClient::SessionManager.new(@client)
    assert_nil(mgr.instance_eval { @proxy })
    assert_nil(mgr.debug_dev)
    @client.debug_dev = Object.new
    @client.proxy = 'http://myproxy:12345'
    mgr = HTTPClient::SessionManager.new(@client)
    assert_equal('http://myproxy:12345', mgr.instance_eval { @proxy }.to_s)
    assert_equal(@client.debug_dev, mgr.debug_dev)
  end

  def create_keepalive_disconnected_thread(idx, sock)
    Thread.new {
      # return "12345" for the first connection
      sock.gets
      sock.gets
      sock.write("HTTP/1.1 200 OK\r\n")
      sock.write("Content-Length: 5\r\n")
      sock.write("\r\n")
      sock.write("12345")
      # for the next connection, close while reading the request for emulating
      # KeepAliveDisconnected
      sock.gets
      sock.close
    }
  end

  def test_keepalive_disconnected
    client = HTTPClient.new
    server = TCPServer.open('127.0.0.1', 0)
    server.listen(30) # set enough backlogs
    endpoint = "http://127.0.0.1:#{server.addr[1]}/"
    Thread.new {
      Thread.abort_on_exception = true
      # emulate 10 keep-alive connections
      10.times do |idx|
        sock = server.accept
        create_keepalive_disconnected_thread(idx, sock)
      end
      # return "23456" for the request which gets KeepAliveDisconnected
      5.times do
        sock = server.accept
        sock.gets
        sock.gets
        sock.write("HTTP/1.1 200 OK\r\n")
        sock.write("\r\n")
        sock.write("23456")
        sock.close
      end
      # return "34567" for the rest requests
      while true
        sock = server.accept
        sock.gets
        sock.gets
        sock.write("HTTP/1.1 200 OK\r\n")
        sock.write("Connection: close\r\n")
        sock.write("Content-Length: 5\r\n")
        sock.write("\r\n")
        sock.write("34567")
        sock.close
      end
    }
    # allocate 10 keep-alive connections
    (0...10).to_a.map {
      Thread.new {
        assert_equal("12345", client.get(endpoint).content)
      }
    }.each { |th| th.join }
    # send 5 requests, which should get KeepAliveDesconnected.
    # doing these requests, rest keep-alive connections are invalidated.
    (0...5).to_a.map {
      Thread.new {
        assert_equal("23456", client.get(endpoint).content)
      }
    }.each { |th| th.join }
    # rest requests won't get KeepAliveDisconnected; how can I check this?
    (0...10).to_a.map {
      Thread.new {
        assert_equal("34567", client.get(endpoint).content)
      }
    }.each { |th| th.join }
  end

  def create_keepalive_thread(count, sock)
    Thread.new {
      Thread.abort_on_exception = true
      count.times do
        req = sock.gets
        while line = sock.gets
          break if line.chomp.empty?
        end
        case req
        when /chunked/
          sock.write("HTTP/1.1 200 OK\r\n")
          sock.write("Transfer-Encoding: chunked\r\n")
          sock.write("\r\n")
          sock.write("1a\r\n")
          sock.write("abcdefghijklmnopqrstuvwxyz\r\n")
          sock.write("10\r\n")
          sock.write("1234567890abcdef\r\n")
          sock.write("0\r\n")
          sock.write("\r\n")
        else
          sock.write("HTTP/1.1 200 OK\r\n")
          sock.write("Content-Length: 5\r\n")
          sock.write("\r\n")
          sock.write("12345")
        end
      end
      sock.close
    }
  end

  def test_keepalive
    server = TCPServer.open('localhost', 0)
    server_thread = Thread.new {
      Thread.abort_on_exception = true
      sock = server.accept
      create_keepalive_thread(10, sock)
    }
    url = "http://localhost:#{server.addr[1]}/"
    begin
      # content-length
      5.times do
        assert_equal('12345', @client.get(url).body)
      end
      # chunked
      5.times do
        assert_equal('abcdefghijklmnopqrstuvwxyz1234567890abcdef', @client.get(url + 'chunked').body)
      end
    ensure
      server.close
      server_thread.join
    end
  end

  def test_socket_local
    @client.socket_local.host = '127.0.0.1'
    assert_equal('hello', @client.get_content(serverurl + 'hello'))
    @client.reset_all
    @client.socket_local.port = serverport
    begin
      @client.get_content(serverurl + 'hello')
    rescue Errno::EADDRINUSE, SocketError
      assert(true)
    end
  end

  def test_body_param_order
    ary = ('b'..'d').map { |k| ['key2', k] } << ['key1', 'a'] << ['key3', 'z']
    assert_equal("key2=b&key2=c&key2=d&key1=a&key3=z", HTTP::Message.escape_query(ary))
  end

  if RUBY_VERSION > "1.9"
    def test_charset
      body = @client.get(serverurl + 'charset').body
      assert_equal(Encoding::EUC_JP, body.encoding)
      assert_equal('あいうえお'.encode(Encoding::EUC_JP), body)
    end
  end

private

  def check_query_get(query)
    WEBrick::HTTPUtils.parse_query(
      @client.get(serverurl + 'servlet', query).header["x-query"][0]
    )
  end

  def check_query_post(query)
    WEBrick::HTTPUtils.parse_query(
      @client.post(serverurl + 'servlet', query).header["x-query"][0]
    )
  end

  def setup_server
    @server = WEBrick::HTTPServer.new(
      :BindAddress => "localhost",
      :Logger => @logger,
      :Port => 0,
      :AccessLog => [],
      :DocumentRoot => File.dirname(File.expand_path(__FILE__))
    )
    @serverport = @server.config[:Port]
    [:hello, :sleep, :servlet_redirect, :redirect1, :redirect2, :redirect3, :redirect_self, :relative_redirect, :chunked, :largebody, :status, :compressed, :charset].each do |sym|
      @server.mount(
	"/#{sym}",
	WEBrick::HTTPServlet::ProcHandler.new(method("do_#{sym}").to_proc)
      )
    end
    @server.mount('/servlet', TestServlet.new(@server))
    @server_thread = start_server_thread(@server)
  end

  def escape_noproxy
    backup = HTTPClient::NO_PROXY_HOSTS.dup
    HTTPClient::NO_PROXY_HOSTS.clear
    yield
  ensure
    HTTPClient::NO_PROXY_HOSTS.replace(backup)
  end

  def do_hello(req, res)
    res['content-type'] = 'text/html'
    res.body = "hello"
  end

  def do_sleep(req, res)
    sec = req.query['sec'].to_i
    sleep sec
    res['content-type'] = 'text/html'
    res.body = "hello"
  end

  def do_servlet_redirect(req, res)
    res.set_redirect(WEBrick::HTTPStatus::Found, serverurl + "servlet") 
  end

  def do_redirect1(req, res)
    res.set_redirect(WEBrick::HTTPStatus::MovedPermanently, serverurl + "hello") 
  end

  def do_redirect2(req, res)
    res.set_redirect(WEBrick::HTTPStatus::TemporaryRedirect, serverurl + "redirect3")
  end

  def do_redirect3(req, res)
    res.set_redirect(WEBrick::HTTPStatus::Found, serverurl + "hello") 
  end

  def do_redirect_self(req, res)
    res.set_redirect(WEBrick::HTTPStatus::Found, serverurl + "redirect_self") 
  end

  def do_relative_redirect(req, res)
    res.set_redirect(WEBrick::HTTPStatus::Found, "hello") 
  end

  def do_chunked(req, res)
    res.chunked = true
    piper, pipew = IO.pipe
    res.body = piper
    pipew << req.query['msg']
    pipew.close
  end

  def do_largebody(req, res)
    res['content-type'] = 'text/html'
    res.body = "a" * 1000 * 1000
  end

  def do_compressed(req, res)
    res['content-type'] = 'application/octet-stream'
    if req.query['enc'] == 'gzip'
      res['content-encoding'] = 'gzip'
      res.body = GZIP_CONTENT
    elsif req.query['enc'] == 'deflate'
      res['content-encoding'] = 'deflate'
      res.body = DEFLATE_CONTENT
    end
  end

  def do_charset(req, res)
    if RUBY_VERSION > "1.9"
      res.body = 'あいうえお'.encode("euc-jp")
      res['Content-Type'] = 'text/plain; charset=euc-jp'
    else
      res.body = 'this endpoint is for 1.9 or later'
    end
  end

  def do_status(req, res)
    res.status = req.query['status'].to_i
  end

  class TestServlet < WEBrick::HTTPServlet::AbstractServlet
    def get_instance(*arg)
      self
    end

    def do_HEAD(req, res)
      res["x-head"] = 'head'	# use this for test purpose only.
      res["x-query"] = query_response(req)
    end

    def do_GET(req, res)
      res.body = 'get'
      res["x-query"] = query_response(req)
    end

    def do_POST(req, res)
      res["content-type"] = "text/plain" # iso-8859-1, not US-ASCII
      res.body = 'post,' + req.body.to_s
      res["x-query"] = body_response(req)
    end

    def do_PUT(req, res)
      res["x-query"] = body_response(req)
      param = WEBrick::HTTPUtils.parse_query(req.body) || {}
      res["x-size"] = (param['txt'] || '').size
      res.body = param['txt'] || 'put'
    end

    def do_DELETE(req, res)
      res.body = 'delete'
    end

    def do_OPTIONS(req, res)
      # check RFC for legal response.
      res.body = 'options'
    end

    def do_PROPFIND(req, res)
      res.body = 'propfind'
    end

    def do_PROPPATCH(req, res)
      res.body = 'proppatch'
      res["x-query"] = body_response(req)
    end

    def do_TRACE(req, res)
      # client SHOULD reflect the message received back to the client as the
      # entity-body of a 200 (OK) response. [RFC2616]
      res.body = 'trace'
      res["x-query"] = query_response(req)
    end

  private

    def query_response(req)
      query_escape(WEBrick::HTTPUtils.parse_query(req.query_string))
    end

    def body_response(req)
      query_escape(WEBrick::HTTPUtils.parse_query(req.body))
    end

    def query_escape(query)
      escaped = []
      query.sort_by { |k, v| k }.collect do |k, v|
	v.to_ary.each do |ve|
	  escaped << CGI.escape(k) + '=' + CGI.escape(ve)
	end
      end
      escaped.join('&')
    end
  end
end
