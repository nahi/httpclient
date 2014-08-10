# coding: utf-8
require 'spec_helper'

describe 'HTTPClient' do
  before :each do
    @client = HTTPClient.new
  end

  it "initialize" do
    without_noproxy do
      @proxy.io.string = ""
      @client = HTTPClient.new(@proxy.u)
      expect(@client.proxy).to eq(urify(@proxy.u))
      expect(@client.head(@srv.u).status).to eq(200)
      expect(@proxy.io.string).to match(/accept/)
    end
  end
  
  it "agent name" do
    @client = HTTPClient.new(nil, "agent_name_foo")
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u)
    lines = str.split(/(?:\r?\n)+/)
    expect(lines[0]).to eq("= Request")
    expect(lines[4]).to match /^User-Agent: agent_name_foo/
  end
  
  it "from" do
    @client = HTTPClient.new(nil, nil, "from_bar")
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u)
    lines = str.split(/(?:\r?\n)+/)
    expect(lines[0]).to eq("= Request")
    expect(lines[5]).to match /^From: from_bar/
  end
  
  it "debug dev" do
    str = ""
    @client.debug_dev = str
    expect(@client.debug_dev.object_id).to eq(str.object_id)
    expect(str.empty?).to be_truthy
    @client.get(@srv.u)
    expect(str.empty?).to be_falsey
  end
  
  it "debug dev stream" do
    str = ""
    @client.debug_dev = str
    conn = @client.get_async(@srv.u)
    until conn.finished?
      Thread.pass
    end
    expect(str.empty?).to be_falsey
  end
  
  it "host given" do
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u)
    lines = str.split(/(?:\r?\n)+/)
    expect(lines[0]).to eq("= Request")
    expect(lines[2]).to eq("! CONNECTION ESTABLISHED")
    expect(lines[3]).to eq("GET / HTTP/1.1")
    expect(lines[7]).to eq("Host: localhost:#{@srv.port}")
    @client.reset_all
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u, nil, "Host" => "foo")
    lines = str.split(/(?:\r?\n)+/)
    expect(lines[0]).to eq("= Request")
    expect(lines[2]).to eq("! CONNECTION ESTABLISHED")
    expect(lines[3]).to eq("GET / HTTP/1.1")
    expect(lines[4]).to eq("Host: foo")
  end
  
  it "redirect returns not modified" do
    timeout(2) do
      @client.get(@srv.u("status"), {:status => 306}, :follow_redirect => true)
    end
  end
  
  it "proxy" do
    without_noproxy do
      begin
        @client.proxy = "http://"
      rescue
        expect($!.class.to_s).to match(/InvalidURIError/)
      end
      @client.proxy = ""
      expect(@client.proxy).to be_nil
      @client.proxy = "http://admin:admin@foo:1234"
      expect(@client.proxy).to eq(urify("http://admin:admin@foo:1234"))
      uri = urify("http://bar:2345")
      @client.proxy = uri
      expect(@client.proxy).to eq(uri)
      @proxy.io.string = ""
      @client.proxy = nil
      expect(@client.head(@srv.u).status).to eq(200)
      expect(@proxy.io.string).not_to match(/accept/)
      @proxy.io.string = ""
      @client.proxy = @proxy.u
      @client.debug_dev = str = ""
      expect(@client.head(@srv.u).status).to eq(200)
      expect(@proxy.io.string).to match(/accept/)
      expect(str).to match(/Host: localhost:#{@srv.port}/)
    end
  end
  
  it "host header" do
    @client.proxy = @proxy.u
    @client.debug_dev = str = ""
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\r\n\r\n"
    expect(@client.head("http://www.example.com/foo").status).to eq(200)
    expect(/\r\nHost: www\.example\.com\r\n/ =~ str).to be_truthy
    @client.debug_dev = str = ""
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\r\n\r\n"
    expect(@client.head('http://www.example.com:12345/foo').status).to eq 200
    expect(str).to match(/\r\nHost: www\.example\.com:12345\r\n/)
  end
  
  it "proxy env" do
    ClimateControl.modify http_proxy: 'http://admin:admin@foo:1234', NO_PROXY: 'foobar' do
      client = HTTPClient.new
      expect(client.proxy).to eq(urify("http://admin:admin@foo:1234"))
      expect(client.no_proxy).to eq("foobar")
    end
  end
  
  it "proxy env cgi" do
    ClimateControl.modify http_proxy: 'http://admin:admin@foo:1234', NO_PROXY: 'foobar', REQUEST_METHOD: 'GET' do
      client = HTTPClient.new
      expect(client.proxy).to eq(nil)
      ClimateControl.modify CGI_HTTP_PROXY: 'http://admin:admin@foo:1234' do
        client = HTTPClient.new
        expect(client.proxy).to eq(urify("http://admin:admin@foo:1234"))
      end
    end
  end
  
  it "empty proxy env" do
    ClimateControl.modify http_proxy: '' do
      client = HTTPClient.new
      expect(client.proxy).to eq(nil)
    end
  end
  
  it "noproxy for localhost" do
    @proxy.io.string = ""
    @client.proxy = @proxy.u
    expect(@client.head(@srv.u).status).to eq(200)
    expect(@proxy.io.string).not_to match(/accept/) 
  end
  
  it "no proxy" do
    without_noproxy do
      expect(@client.no_proxy).to eq(nil)
      @client.no_proxy = "localhost"
      expect(@client.no_proxy).to eq("localhost")

      @proxy.io.string = ""
      @client.proxy = nil
      expect(@client.head(@srv.u).status).to eq(200)
      expect(@proxy.io.string).not_to match(/accept/) 

      @proxy.io.string = ""
      @client.proxy = @proxy.u
      expect(@client.head(@srv.u).status).to eq(200)
      expect(@proxy.io.string).not_to match(/accept/) 

      @proxy.io.string = ""
      @client.no_proxy = "foobar"
      @client.proxy = @proxy.u
      expect(@client.head(@srv.u).status).to eq(200)
      expect(@proxy.io.string).to match(/accept/) 

      @proxy.io.string = ""
      @client.no_proxy = "foobar,localhost:baz"
      @client.proxy = @proxy.u
      expect(@client.head(@srv.u).status).to eq(200)
      expect(@proxy.io.string).not_to match(/accept/) 

      @proxy.io.string = ""
      @client.no_proxy = "foobar,localhost:443"
      @client.proxy = @proxy.u
      expect(@client.head(@srv.u).status).to eq(200)
      expect(@proxy.io.string).to match(/accept/) 

      @proxy.io.string = ""
      @client.no_proxy = "foobar,localhost:443:localhost:#{@srv.port},baz"
      @client.proxy = @proxy.u
      expect(@client.head(@srv.u).status).to eq(200)
      expect(@proxy.io.string).not_to match(/accept/) 
    end
  end
  
  describe "no proxy with initial dot" do
    before :each do
      @client.debug_dev = @str = ""
      @client.test_loopback_http_response << "HTTP/1.0 200 OK\r\n\r\n"
      @client.proxy = @proxy.u

    end
    it 'via proxy' do
      @client.no_proxy = ""
      @client.head("http://www.foo.com")
      expect(@str).to match(/CONNECT TO localhost/)
    end
    it 'no proxy because .foo.com matches with www.foo.com' do
      @client.no_proxy = ".foo.com"
      @client.head("http://www.foo.com")
      expect(@str).to match(/CONNECT TO www.foo.com/)
    end
    it 'via proxy because .foo.com does not matche with foo.com' do
      @client.no_proxy = ".foo.com"
      @client.head("http://foo.com")
      expect(@str).to match(/CONNECT TO localhost/)
    end
    it 'no proxy because foo.com matches with foo.com' do
      @client.no_proxy = "foo.com"
      @client.head("http://foo.com")
      expect(@str).to match(/CONNECT TO foo.com/)
    end
  end
  
  it "cookie update while authentication" do
    without_noproxy do
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
      @client.debug_dev = str = ""
      @client.set_auth("http://www.example.org/baz/", "admin", "admin")
      expect(@client.get("http://www.example.org/baz/foo").content).to eq("hello")
      expect(str).to match /^Cookie: foo=bar/
      expect(str).to match /^Authorization: Basic YWRtaW46YWRtaW4=/
    end
  end
  
  it "proxy ssl" do
    without_noproxy do
      @client.proxy = "http://admin:admin@localhost:8080/"
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
      expect(@client.get("https://localhost:17171/baz").content).to eq("hello")
    end
  end
  
  it "loopback response" do
    @client.test_loopback_response << "message body 1"
    @client.test_loopback_response << "message body 2"
    expect(@client.get_content("http://somewhere")).to eq("message body 1")
    expect(@client.get_content("http://somewhere")).to eq("message body 2")
    @client.debug_dev = str = ""
    @client.test_loopback_response << "message body 3"
    expect(@client.get_content("http://somewhere")).to eq("message body 3")
    expect(str).to match /message body 3/
  end
  
  it "loopback response stream" do
    @client.test_loopback_response << "message body 1"
    @client.test_loopback_response << "message body 2"
    conn = @client.get_async("http://somewhere")
    until conn.finished?
      Thread.pass
    end
    expect(conn.pop.content.read).to eq("message body 1")
    conn = @client.get_async("http://somewhere")
    until conn.finished?
      Thread.pass
    end
    expect(conn.pop.content.read).to eq("message body 2")
  end
  
  it "loopback http response" do
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
content-length: 100

message body 1"
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
content-length: 100

message body 2"
    expect(@client.get_content("http://somewhere")).to eq("message body 1")
    expect(@client.get_content("http://somewhere")).to eq("message body 2")
  end
  
  it "multiline header" do
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
X-Foo: XXX
   YYY
X-Bar: 
 XXX
	YYY
content-length: 100

message body 1"
    res = @client.get("http://somewhere")
    expect(res.content).to eq("message body 1")
    expect(res.header["x-foo"]).to eq(["XXX YYY"])
    expect(res.header["x-bar"]).to eq(["XXX YYY"])
  end
  
  it "broken header" do
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
XXXXX
content-length: 100

message body 1"
    res = @client.get("http://somewhere")
    expect(res.content).to eq("message body 1")
  end
  
  it "request uri in response" do
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
content-length: 100

message body"
    expect(@client.get("http://google.com/").header.request_uri).to eq(urify("http://google.com/"))
  end
  
  it "request uri in response when redirect" do
    expected = urify(@srv.u("hello"))
    expect(@client.get(@srv.u("redirect1"), :follow_redirect => true).header.request_uri).to eq(expected)
    expect(@client.get(@srv.u("redirect2"), :follow_redirect => true).header.request_uri).to eq(expected)
  end
  
  describe "redirect" do
    before :each do
      @url = @srv.u('redirect1')
      @https_url = urify(@url)
      @https_url.scheme = 'https'
      @redirect_to_http = "HTTP/1.0 302 OK\nLocation: #{@url}\n\n"
      @redirect_to_https = "HTTP/1.0 302 OK\nLocation: #{@https_url}\n\n"
      @client.reset_all
    end

    # TODO check if this should be present
    pending 'https -> http is denied' do
      @client.test_loopback_http_response << @redirect_to_http
      expect {
         @client.get_content(@https_url)
      }.to raise_error(HTTPClient::BadResponseError)
    end

    it 'http -> http is OK' do
      @client.test_loopback_http_response << @redirect_to_http
      expect(@client.get_content(@url)).to eq 'hello'
    end

    it 'trying to normal endpoint with SSL -> SSL negotiation failure' do
      @client.test_loopback_http_response << @redirect_to_https
      expect {
         @client.get_content(@https_url)
      }.to raise_error(OpenSSL::SSL::SSLError)
    end

    it 'https -> https is OK' do
      @client.reset_all
      @client.test_loopback_http_response << @redirect_to_https
      expect {
         @client.get_content(@https_url)
      }.to raise_error(OpenSSL::SSL::SSLError)
    end

    it 'https -> http with strict_redirect_uri_callback' do
      @client.redirect_uri_callback = @client.method(:strict_redirect_uri_callback)
      @client.test_loopback_http_response << @redirect_to_http
      expect {
         @client.get_content(@https_url)
      }.to raise_error(HTTPClient::BadResponseError)
    end
  end
  
  it "redirect see other" do
    expect(@client.post_content(@srv.u("redirect_see_other"))).to eq("hello")
  end
  
  it "redirect relative" do
    @client.test_loopback_http_response << "HTTP/1.0 302 OK\nLocation: hello\n\n"
    silent do
      expect(@client.get_content(@srv.u('redirect1'))).to eq 'hello'
    end

    @client.reset_all
    @client.redirect_uri_callback = @client.method(:strict_redirect_uri_callback)
    expect(@client.get_content(@srv.u('redirect1'))).to eq 'hello'
    @client.reset_all
    @client.test_loopback_http_response << "HTTP/1.0 302 OK\nLocation: hello\n\n"
    begin
      @client.get_content(@srv.u('redirect1'))
      expect(false).to be_truthy
    rescue HTTPClient::BadResponseError => e
      expect(e.res.status).to eq 302
    end
  end
  
  it "redirect https relative" do
    url = @srv.u("redirect1")
    https_url = urify(url)
    https_url.scheme = "https"
    @client.test_loopback_http_response << "HTTP/1.0 302 OK
Location: /foo

"
    @client.test_loopback_http_response << "HTTP/1.0 200 OK

hello"
    
    silent do
      expect(@client.get_content(https_url)).to eq("hello")
    end
  end
  
  it "no content" do
    timeout(2) do
      @client.get(@srv.u("status"), :status => 101)
      @client.get(@srv.u("status"), :status => 204)
      @client.get(@srv.u("status"), :status => 304)
    end
  end
  
  it "head" do
    expect(@client.head(@srv.u("servlet")).header["x-head"][0]).to eq("head")
    param = {"1" => "2", "3" => "4"}
    res = @client.head(@srv.u("servlet"), param)
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "head async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.head_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "get" do
    expect(@client.get(@srv.u("servlet")).content).to eq("get")
    param = {"1" => "2", "3" => "4"}
    res = @client.get(@srv.u("servlet"), param)
    expect(params(res.header["x-query"][0])).to eq(param)
    expect(res.contenttype).to be_nil
    url = @srv.u("servlet?5=6&7=8")
    res = @client.get(url, param)
    expect(params(res.header["x-query"][0])).to eq(param.merge("5" => "6", "7" => "8"))
    expect(res.contenttype).to be_nil
  end
  
  it "head follow redirect" do
    expected = urify(@srv.u("hello"))
    expect(@client.head(@srv.u("hello"), :follow_redirect => true).header.request_uri).to eq(expected)
    expect(@client.head(@srv.u("redirect1"), :follow_redirect => true).header.request_uri).to eq(expected)
    expect(@client.head(@srv.u("redirect2"), :follow_redirect => true).header.request_uri).to eq(expected)
  end
  
  it "get follow redirect" do
    expect(@client.get(@srv.u("hello"), :follow_redirect => true).body).to eq("hello")
    expect(@client.get(@srv.u("redirect1"), :follow_redirect => true).body).to eq("hello")
    expect(@client.get(@srv.u("redirect2"), :follow_redirect => true).body).to eq("hello")
  end
  
  it "get async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.get_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "get async for largebody" do
    conn = @client.get_async(@srv.u("largebody"))
    res = conn.pop
    expect(res.content.read.length).to eq(1000.*(1000))
  end
  
  it "get with block" do
    called = false
    res = @client.get(@srv.u("servlet")) do |str|
      expect(str).to eq("get")
      called = true
    end
    expect(called).to be_truthy
    expect(res.content).to be_nil
  end
  
  it "get with block chunk string recycle" do
    @client.read_block_size = 2
    body = []
    res = @client.get(@srv.u("servlet")) do |str|
      body << str
    end
    expect(body.size).to eq(2)
    expect(body.join).to eq("get")
  end
  
  it "post" do
    expect(@client.post(@srv.u("servlet")).content[0, 4]).to eq("post")
    param = {"1" => "2", "3" => "4"}
    res = @client.post(@srv.u("servlet"), param)
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "post follow redirect" do
    expect(@client.post(@srv.u("hello"), :follow_redirect => true).body).to eq("hello")
    expect(@client.post(@srv.u("redirect1"), :follow_redirect => true).body).to eq("hello")
    expect(@client.post(@srv.u("redirect2"), :follow_redirect => true).body).to eq("hello")
  end
  
  it "post with content type" do
    param = [["1", "2"], ["3", "4"]]
    ext = {"content-type" => "application/x-www-form-urlencoded", "hello" => "world"}
    expect(@client.post(@srv.u("servlet")).content[0, 4]).to eq("post")
    res = @client.post(@srv.u("servlet"), param, ext)
    expect(params(res.header["x-query"][0])).to eq(Hash[param])
    ext = [["content-type", "multipart/form-data"], ["hello", "world"]]
    expect(@client.post(@srv.u("servlet")).content[0, 4]).to eq("post")
    res = @client.post(@srv.u("servlet"), param, ext)
    expect(res.content).to match /Content-Disposition: form-data; name="1"/
    expect(res.content).to match /Content-Disposition: form-data; name="3"/
    ext = {"content-type" => "multipart/form-data; boundary=hello"}
    expect(@client.post(@srv.u("servlet")).content[0, 4]).to eq("post")
    res = @client.post(@srv.u("servlet"), param, ext)
    expect(res.content).to match /Content-Disposition: form-data; name="1"/
    expect(res.content).to match /Content-Disposition: form-data; name="3"/
    expect(res.content).to eq("post,--hello\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n2\r\n--hello\r\nContent-Disposition: form-data; name=\"3\"\r\n\r\n4\r\n--hello--\r\n\r\n")
  end
  
  it "post with custom multipart and boolean params" do
    param = [["boolean_true", true]]
    ext = {"content-type" => "multipart/form-data"}
    expect(@client.post(@srv.u("servlet")).content[0, 4]).to eq("post")
    res = @client.post(@srv.u("servlet"), param, ext)
    expect(res.content).to match /Content-Disposition: form-data; name="boolean_true"\r\n\r\ntrue\r\n/

    param = [["boolean_false", false]]
    res = @client.post(@srv.u("servlet"), param, ext)
    expect(res.content).to match /Content-Disposition: form-data; name="boolean_false"\r\n\r\nfalse\r\n/

    param = [["nil", nil]]
    res = @client.post(@srv.u("servlet"), param, ext)
    expect(res.content).to match /Content-Disposition: form-data; name="nil"\r\n\r\n\r\n/
  end
  
  it "post with file" do
    STDOUT.sync = true
    File.open(__FILE__) do |file|
      res = @client.post(@srv.u("servlet"), 1 => 2, 3 => file)
      expect(res.content).to match /^Content-Disposition: form-data; name="1"\r\n/mn
      expect(res.content).to match /^Content-Disposition: form-data; name="3";/
      expect(res.content).to match /FIND_TAG_IN_THIS_FILE/
    end
  end
  
  it "post with file without size" do
    STDOUT.sync = true
    File.open(__FILE__) do |file|
      def file.size
        raise SystemCallError.new("Unknown Error (20047)")
      end
      
      @client.post(@srv.u("servlet"), 1 => 2, 3 => file)
    end
  end
  
  it "post with io" do
    myio = StringIO.new("X".*(HTTP::Message::Body::DEFAULT_CHUNK_SIZE + 1))
    def myio.read(*args)
      @called ||= 0
      @called = @called + 1
      super
    end
    
    def myio.called
      @called
    end
    @client.debug_dev = str = StringIO.new
    res = @client.post(@srv.u("servlet"), 1 => 2, 3 => myio)
    expect(res.content).to match /\r\nContent-Disposition: form-data; name="1"\r\n/m
    expect(res.content).to match /\r\n2\r\n/m
    expect(res.content).to match /\r\nContent-Disposition: form-data; name="3"; filename=""\r\n/m
    expect(str.string).to match /\r\nContent-Length:/m
    expect(myio.called).to eq(3)
  end
  
  it "post with io nosize" do
    myio = StringIO.new("4")
    def myio.size
      nil
    end
    @client.debug_dev = str = StringIO.new
    res = @client.post(@srv.u("servlet"), {1 => 2, 3 => myio})
    expect(res.content).to match /\r\nContent-Disposition: form-data; name="1"\r\n/m
    expect(res.content).to match /\r\n2\r\n/m
    expect(res.content).to match /\r\nContent-Disposition: form-data; name="3"; filename=""\r\n/m
    expect(res.content).to match /\r\n4\r\n/m
    # TODO is this needed?
    #res.content.should match /\r\nTransfer-Encoding: chunked\r\n/m
  end
  
  it "post async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.post_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "post with block" do
    called = false
    res = @client.post(@srv.u("servlet")) do |str|
      expect(str).to eq("post,")
      called = true
    end
    expect(called).to be_truthy
    expect(res.content).to be_nil
    called = false
    param = [["1", "2"], ["3", "4"]]
    res = @client.post(@srv.u("servlet"), param) do |str|
      expect(str).to eq("post,1=2&3=4")
      called = true
    end
    expect(called).to be_truthy
    expect(res.header["x-query"][0]).to eq("1=2&3=4")
    expect(res.content).to be_nil
  end
  
  it "post with custom multipart" do
    ext = {"content-type" => "multipart/form-data"}
    expect(@client.post(@srv.u("servlet")).content[0, 4]).to eq("post")
    body = [{ 'Content-Disposition' => 'form-data; name="1"', :content => "2"},
            { 'Content-Disposition' => 'form-data; name="3"', :content => "4"}]
    res = @client.post(@srv.u("servlet"), body, ext)
    expect(res.content).to match /Content-Disposition: form-data; name="1"/
    expect(res.content).to match /Content-Disposition: form-data; name="3"/
    ext = {"content-type" => "multipart/form-data; boundary=hello"}
    expect(@client.post(@srv.u("servlet")).content[0, 4]).to eq("post")
    res = @client.post(@srv.u("servlet"), body, ext)
    expect(res.content).to match /Content-Disposition: form-data; name="1"/
    expect(res.content).to match /Content-Disposition: form-data; name="3"/
    expect(res.content).to eq("post,--hello\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n2\r\n--hello\r\nContent-Disposition: form-data; name=\"3\"\r\n\r\n4\r\n--hello--\r\n\r\n")
  end
  
  it "post with custom multipart and file" do
    STDOUT.sync = true
    File.open(__FILE__) do |file|
      ext = {"Content-Type" => "multipart/alternative"}
      body = [{"Content-Type" => "text/plain", :content => "this is only a test"}, {"Content-Type" => "application/x-ruby", :content => file}]
      res = @client.post(@srv.u("servlet"), body, ext)
      expect(res.content).to match /^Content-Type: text\/plain\r\n/m
      expect(res.content).to match /^this is only a test\r\n/m
      expect(res.content).to match /^Content-Type: application\/x-ruby\r\n/m
      expect(res.content).to match /FIND_TAG_IN_THIS_FILE/
    end
  end
  
  it "put" do
    expect(@client.put(@srv.u("servlet")).content).to eq("put")
    param = {"1" => "2", "3" => "4"}
    @client.debug_dev = str = ""
    res = @client.put(@srv.u("servlet"), param)
    expect(params(res.header["x-query"][0])).to eq(param)
    expect(str.split(/\r?\n/)[5]).to eq("Content-Type: application/x-www-form-urlencoded")
  end
  
  it "put bytesize" do
    res = @client.put(@srv.u("servlet"), "txt" => "あいうえお")
    expect(res.header["x-query"][0]).to eq("txt=%E3%81%82%E3%81%84%E3%81%86%E3%81%88%E3%81%8A")
    expect(res.header["x-size"][0]).to eq("15")
  end
  
  it "put async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.put_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "patch" do
    expect(@client.patch(@srv.u("servlet")).content).to eq("patch")
    param = {"1" => "2", "3" => "4"}
    @client.debug_dev = str = ""
    res = @client.patch(@srv.u("servlet"), param)
    expect(params(res.header["x-query"][0])).to eq(param)
    expect(str.split(/\r?\n/)[5]).to eq("Content-Type: application/x-www-form-urlencoded")
  end
  
  it "patch async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.patch_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "delete" do
    expect(@client.delete(@srv.u("servlet")).content).to eq("delete")
  end
  
  it "delete with body" do
    param = {'1'=>'2', '3'=>'4'}
    @client.debug_dev = str = ''
    expect(@client.delete(@srv.u('servlet'), param).content).to eq "delete"
    expect(HTTP::Message.parse(str.split(/\r?\n\r?\n/)[2])).to eq({'1' => ['2'], '3' => ['4']})
  end
  
  it "delete async" do
    conn = @client.delete_async(@srv.u("servlet"))
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(res.content.read).to eq("delete")
  end
  
  it "options" do
    expect(@client.options(@srv.u("servlet")).content).to eq("options")
  end
  
  it "options async" do
    conn = @client.options_async(@srv.u("servlet"))
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(res.content.read).to eq("options")
  end
  
  it "propfind" do
    expect(@client.propfind(@srv.u("servlet")).content).to eq("propfind")
  end
  
  it "propfind async" do
    conn = @client.propfind_async(@srv.u("servlet"))
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(res.content.read).to eq("propfind")
  end
  
  it "proppatch" do
    expect(@client.proppatch(@srv.u("servlet")).content).to eq("proppatch")
    param = {"1" => "2", "3" => "4"}
    res = @client.proppatch(@srv.u("servlet"), param)
    expect(res.content).to eq("proppatch")
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "proppatch async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.proppatch_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(res.content.read).to eq("proppatch")
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "trace" do
    expect(@client.trace(@srv.u("servlet")).content).to eq("trace")
    param = {"1" => "2", "3" => "4"}
    res = @client.trace(@srv.u("servlet"), param)
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "trace async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.trace_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    expect(params(res.header["x-query"][0])).to eq(param)
  end
  
  it "chunked" do
    expect(@client.get_content(@srv.u("chunked"), "msg" => "chunked")).to eq("chunked")
    expect(@client.get_content(@srv.u("chunked"), "msg" => "あいうえお")).to eq("あいうえお")
  end
  
  it "chunked empty" do
    expect(@client.get_content(@srv.u("chunked"), "msg" => "")).to eq("")
  end
  
  it "get query" do
    expect(check_query_get({1=>2})).to eq({'1'=>'2'})
    expect(check_query_get({"a"=>"A", "B"=>"b"})).to eq({'a'=>'A', 'B'=>'b'})
    expect(check_query_get({"&"=>"&"})).to eq({'&'=>'&'})
    expect(check_query_get({"= "=>" =+"})).to eq({'= '=>' =+'})
    expect(['=', '&'].sort).to eq check_query_get([["=", "="], ["=", "&"]])['='].to_ary.sort

    expect({'123'=>'45'}).to eq check_query_get('123=45')
    expect({'12 3'=>'45', ' '=>' '}).to eq check_query_get('12+3=45&+=+')
    expect({}).to eq check_query_get('')
    expect({'1'=>'2'}).to eq check_query_get({1=>StringIO.new('2')})
    expect({'1'=>'2', '3'=>'4'}).to eq check_query_get(StringIO.new('3=4&1=2'))

    hash = check_query_get({"a"=>["A","a"], "B"=>"b"})
    expect({'a'=>'A', 'B'=>'b'}).to eq hash
    expect(['A','a']).to eq hash['a'].to_ary

    hash = check_query_get({"a"=>WEBrick::HTTPUtils::FormData.new("A","a"), "B"=>"b"})
    expect({'a'=>'A', 'B'=>'b'}).to eq hash
    expect(['A','a']).to eq hash['a'].to_ary

    hash = check_query_get({"a"=>[StringIO.new("A"),StringIO.new("a")], "B"=>StringIO.new("b")})
    expect({'a'=>'A', 'B'=>'b'}).to eq hash
    expect(['A','a']).to eq hash['a'].to_ary
  end
  
  it "post body" do
    expect(check_query_post(1 => 2)).to eq({"1" => "2"})
    expect(check_query_post("a" => "A", "B" => "b")).to eq({"a" => "A", "B" => "b"})
    expect(check_query_post("&" => "&")).to eq({"&" => "&"})
    expect(check_query_post("= " => " =+")).to eq({"= " => " =+"})
    expect(check_query_post([["=", "="], ["=", "&"]])["="].to_ary.sort).to eq(["=", "&"].sort)
    expect(check_query_post("123=45")).to eq({"123" => "45"})
    expect(check_query_post("12+3=45&+=+")).to eq({"12 3" => "45", " " => " "})
    expect(check_query_post("")).to eq({})
    post_body = StringIO.new("foo=bar&foo=baz")
    expect(check_query_post(post_body)["foo"].to_ary.sort).to eq(["bar", "baz"])
  end
  
  it "extra headers" do
    str = ""
    @client.debug_dev = str
    @client.head(@srv.u, nil, "ABC" => "DEF")
    lines = str.split(/(?:\r?\n)+/)
    expect(lines[0]).to eq("= Request")
    expect(lines[4]).to match "ABC: DEF"
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u, nil, [["ABC", "DEF"], ["ABC", "DEF"]])
    lines = str.split(/(?:\r?\n)+/)
    expect(lines[0]).to eq("= Request")
    expect(lines[4]).to match "ABC: DEF"
    expect(lines[5]).to match "ABC: DEF"
  end
  
  it "http custom date header" do
    @client.debug_dev = str = ""
    res = @client.get(@srv.u("hello"), :header => {"Date" => "foo"})
    lines = str.split(/(?:\r?\n)+/)
    expect(lines[4]).to eq("Date: foo")
  end
  
  it "timeout" do
    expect(@client.connect_timeout).to eq(60)
    expect(@client.send_timeout).to eq(120)
    expect(@client.receive_timeout).to eq(60)
    @client.connect_timeout = 1
    @client.send_timeout = 2
    @client.receive_timeout = 3
    expect(@client.connect_timeout).to eq(1)
    expect(@client.send_timeout).to eq(2)
    expect(@client.receive_timeout).to eq(3)
  end
  
  it "connect timeout" do
    
  end
  
  it "send timeout" do
    
  end
  
  it "receive timeout" do
    expect(@client.get_content(@srv.u("sleep?sec=2"))).to eq("hello")
    @client.receive_timeout = 1
    expect(@client.get_content(@srv.u("sleep?sec=0"))).to eq("hello")
    
    expect {
      @client.get_content(@srv.u("sleep?sec=2"))
    }.to raise_error(HTTPClient::ReceiveTimeoutError)
    @client.receive_timeout = 3
    expect(@client.get_content(@srv.u("sleep?sec=2"))).to eq("hello")
  end
  
  it "receive timeout post" do
    expect(@client.post(@srv.u("sleep"), :sec => 2).content).to eq("hello")
    @client.receive_timeout = 1
    expect(@client.post(@srv.u("sleep"), :sec => 0).content).to eq("hello")
    
    expect {
      @client.post(@srv.u("sleep"), :sec => 2)\
    }.to raise_error(HTTPClient::ReceiveTimeoutError)

    @client.receive_timeout = 3
    expect(@client.post(@srv.u("sleep"), :sec => 2).content).to eq("hello")
  end
  
  it "reset" do
    url = @srv.u("servlet")
    5.times do
      @client.get(url)
      @client.reset(url)
    end
  end
  
  it "reset all" do
    5.times do
      @client.get(@srv.u("servlet"))
      @client.reset_all
    end
  end
  
  it "cookies" do
    cookiefile = File.join(File.dirname(File.expand_path(__FILE__)), "test_cookies_file")
    File.open(cookiefile, "wb") do |f|
      f << "http://rubyforge.org/account/login.php	session_ser	LjEwMy45Ni40Ni0q%2A-fa0537de8cc31	2000000000	.rubyforge.org	/	13
"
    end
    
    @client.set_cookie_store(cookiefile)
    cookie = @client.cookie_manager.cookies.first
    url = cookie.url
    expect(cookie.domain_match(url.host, cookie.domain)).to be_truthy
    @client.reset_all
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
Set-Cookie: foo=bar; expires=#{Time.at(1924873200).gmtime.httpdate}

OK"
    @client.get_content("http://rubyforge.org/account/login.php")
    @client.save_cookie_store
    str = File.read(cookiefile)
    expect(str).to match /http:\/\/rubyforge.org\/account\/login.php\tfoo\tbar\t1924873200\trubyforge.org\t\/account\t1/
    File.unlink(cookiefile)
  end
  
  it "eof error length" do
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
    @client.get('http://foo/bar')
  end
  
  it "eof error rest" do
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
    @client.get('http://foo/bar')
  end
  
  it "connection" do
    c = HTTPClient::Connection.new
    expect(c.finished?).to be_truthy
    expect(c.join).to be_nil
  end
  
  it "site" do
    site = HTTPClient::Site.new
    expect(site.scheme).to eq("tcp")
    expect(site.host).to eq("0.0.0.0")
    expect(site.port).to eq(0)
    expect(site.addr).to eq("tcp://0.0.0.0:0")
    expect(site.to_s).to eq("tcp://0.0.0.0:0")
    
    site.inspect
    site = HTTPClient::Site.new(urify("http://localhost:12345/foo"))
    expect(site.scheme).to eq("http")
    expect(site.host).to eq("localhost")
    expect(site.port).to eq(12345)
    expect(site.addr).to eq("http://localhost:12345")
    expect(site.to_s).to eq("http://localhost:12345")
    
    site.inspect
    site1 = HTTPClient::Site.new(urify("http://localhost:12341/"))
    site2 = HTTPClient::Site.new(urify("http://localhost:12342/"))
    site3 = HTTPClient::Site.new(urify("http://localhost:12342/"))
    expect(site1).not_to eq(site2)
    h = {site1 => "site1", site2 => "site2"}
    h[site3] = "site3"
    expect(h[site1]).to eq("site1")
    expect(h[site2]).to eq("site3")
  end
  
  it "http header" do
    res = @client.get(@srv.u("hello"))
    expect(res.contenttype).to eq("text/html")
    expect(res.header.get(nil).size).to eq(5)
    res.header.delete("connection")
    expect(res.header.get(nil).size).to eq(4)
    res.header["foo"] = "bar"
    expect(res.header["foo"]).to eq(["bar"])
    expect(res.header.get("foo")).to eq([["foo", "bar"]])
    res.header["foo"] = ["bar", "bar2"]
    expect(res.header.get("foo")).to eq([["foo", "bar"], ["foo", "bar2"]])
  end
  
  it "session manager" do
    mgr = HTTPClient::SessionManager.new(@client)
    expect(mgr.instance_eval do
      @proxy
    end).to be_nil
    expect(mgr.debug_dev).to be_nil
    @client.debug_dev = Object.new
    @client.proxy = "http://myproxy:12345"
    mgr = HTTPClient::SessionManager.new(@client)
    expect(mgr.instance_eval do
      @proxy
    end.to_s).to eq("http://myproxy:12345")
    expect(mgr.debug_dev).to eq(@client.debug_dev)
  end
  
  it "socket local" do
    @client.socket_local.host = '127.0.0.1'
    expect(@client.get_content(@srv.u('hello'))).to eq('hello')
    @client.reset_all
    @client.socket_local.port = @srv.port
    begin
      @client.get_content(@srv.u('hello'))
    rescue Errno::EADDRINUSE, SocketError
    end
  end
  
  it "body param order" do
    ary = ("b".."d").map do |k|
      ["key2", k]
    end << ["key1", "a"] << ["key3", "z"]
    expect(HTTP::Message.escape_query(ary)).to eq("key2=b&key2=c&key2=d&key1=a&key3=z")
  end
  it 'charset' do
    body = @client.get(@srv.u("charset")).body
    expect(body.encoding).to eq(Encoding::EUC_JP)
    expect(body).to eq("あいうえお".encode(Encoding::EUC_JP))
  end
  it 'continue' do
    @client.debug_dev = str = ''
    res = @client.get(@srv.u('continue'), :header => {:Expect => '100-continue'})
    expect(res.status).to eq 200
    expect(res.body).to eq 'done!'
    expect(str).to match /Expect: 100-continue/
  end

  it 'ipv6' do
    begin
      server = TCPServer.open('::1', 0)
    rescue
      next # Skip if IPv6 is unavailable.
    end
    server_thread = Thread.new {
      Thread.abort_on_exception = true
      sock = server.accept
      while line = sock.gets
        break if line.chomp.empty?
      end
      sock.write("HTTP/1.1 200 OK\r\n")
      sock.write("Content-Length: 5\r\n")
      sock.write("\r\n")
      sock.write("12345")
      sock.close
    }
    uri = "http://[::1]:#{server.addr[1]}/"
    begin
      expect(@client.get(uri).body).to eq '12345'
    ensure
      server.close
      server_thread.kill
      server_thread.join
    end
  end
end
