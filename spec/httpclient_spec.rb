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
      @client.proxy.should == urify(@proxy.u)
      @client.head(@srv.u).status.should == 200
      @proxy.io.string.should =~ /accept/
    end
  end
  
  it "agent name" do
    @client = HTTPClient.new(nil, "agent_name_foo")
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u)
    lines = str.split(/(?:\r?\n)+/)
    lines[0].should == "= Request"
    lines[4].should match /^User-Agent: agent_name_foo/
  end
  
  it "from" do
    @client = HTTPClient.new(nil, nil, "from_bar")
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u)
    lines = str.split(/(?:\r?\n)+/)
    lines[0].should == "= Request"
    lines[5].should match /^From: from_bar/
  end
  
  it "debug dev" do
    str = ""
    @client.debug_dev = str
    @client.debug_dev.object_id.should == str.object_id
    str.empty?.should be_true
    @client.get(@srv.u)
    str.empty?.should be_false
  end
  
  it "debug dev stream" do
    str = ""
    @client.debug_dev = str
    conn = @client.get_async(@srv.u)
    until conn.finished?
      Thread.pass
    end
    str.empty?.should be_false
  end
  
  it "host given" do
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u)
    lines = str.split(/(?:\r?\n)+/)
    lines[0].should == "= Request"
    lines[2].should == "! CONNECTION ESTABLISHED"
    lines[3].should == "GET / HTTP/1.1"
    lines[7].should == "Host: localhost:#{@srv.port}"
    @client.reset_all
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u, nil, "Host" => "foo")
    lines = str.split(/(?:\r?\n)+/)
    lines[0].should == "= Request"
    lines[2].should == "! CONNECTION ESTABLISHED"
    lines[3].should == "GET / HTTP/1.1"
    lines[4].should == "Host: foo"
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
        $!.class.to_s.should match(/InvalidURIError/)
      end
      @client.proxy = ""
      @client.proxy.should be_nil
      @client.proxy = "http://admin:admin@foo:1234"
      @client.proxy.should == urify("http://admin:admin@foo:1234")
      uri = urify("http://bar:2345")
      @client.proxy = uri
      @client.proxy.should == uri
      @proxy.io.string = ""
      @client.proxy = nil
      @client.head(@srv.u).status.should == 200
      @proxy.io.string.should_not =~ /accept/
      @proxy.io.string = ""
      @client.proxy = @proxy.u
      @client.debug_dev = str = ""
      @client.head(@srv.u).status.should == 200
      @proxy.io.string.should =~ /accept/
      str.should =~ /Host: localhost:#{@srv.port}/
    end
  end
  
  it "host header" do
    @client.proxy = @proxy.u
    @client.debug_dev = str = ""
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\r\n\r\n"
    @client.head("http://www.example.com/foo").status.should == 200
    (/\r\nHost: www\.example\.com\r\n/ =~ str).should be_true
    @client.debug_dev = str = ""
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\r\n\r\n"
    @client.head('http://www.example.com:12345/foo').status.should eq 200
    str.should =~ /\r\nHost: www\.example\.com:12345\r\n/
  end
  
  it "proxy env" do
    ClimateControl.modify http_proxy: 'http://admin:admin@foo:1234', NO_PROXY: 'foobar' do
      client = HTTPClient.new
      client.proxy.should == urify("http://admin:admin@foo:1234")
      client.no_proxy.should == "foobar"
    end
  end
  
  it "proxy env cgi" do
    ClimateControl.modify http_proxy: 'http://admin:admin@foo:1234', NO_PROXY: 'foobar', REQUEST_METHOD: 'GET' do
      client = HTTPClient.new
      client.proxy.should == nil
      ClimateControl.modify CGI_HTTP_PROXY: 'http://admin:admin@foo:1234' do
        client = HTTPClient.new
        client.proxy.should == urify("http://admin:admin@foo:1234")
      end
    end
  end
  
  it "empty proxy env" do
    ClimateControl.modify http_proxy: '' do
      client = HTTPClient.new
      client.proxy.should == nil
    end
  end
  
  it "noproxy for localhost" do
    @proxy.io.string = ""
    @client.proxy = @proxy.u
    @client.head(@srv.u).status.should == 200
    @proxy.io.string.should_not =~ /accept/ 
  end
  
  it "no proxy" do
    without_noproxy do
      @client.no_proxy.should == nil
      @client.no_proxy = "localhost"
      @client.no_proxy.should == "localhost"

      @proxy.io.string = ""
      @client.proxy = nil
      @client.head(@srv.u).status.should == 200
      @proxy.io.string.should_not =~ /accept/ 

      @proxy.io.string = ""
      @client.proxy = @proxy.u
      @client.head(@srv.u).status.should == 200
      @proxy.io.string.should_not =~ /accept/ 

      @proxy.io.string = ""
      @client.no_proxy = "foobar"
      @client.proxy = @proxy.u
      @client.head(@srv.u).status.should == 200
      @proxy.io.string.should =~ /accept/ 

      @proxy.io.string = ""
      @client.no_proxy = "foobar,localhost:baz"
      @client.proxy = @proxy.u
      @client.head(@srv.u).status.should == 200
      @proxy.io.string.should_not =~ /accept/ 

      @proxy.io.string = ""
      @client.no_proxy = "foobar,localhost:443"
      @client.proxy = @proxy.u
      @client.head(@srv.u).status.should == 200
      @proxy.io.string.should =~ /accept/ 

      @proxy.io.string = ""
      @client.no_proxy = "foobar,localhost:443:localhost:#{@srv.port},baz"
      @client.proxy = @proxy.u
      @client.head(@srv.u).status.should == 200
      @proxy.io.string.should_not =~ /accept/ 
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
      @str.should =~ /CONNECT TO localhost/
    end
    it 'no proxy because .foo.com matches with www.foo.com' do
      @client.no_proxy = ".foo.com"
      @client.head("http://www.foo.com")
      @str.should =~ /CONNECT TO www.foo.com/
    end
    it 'via proxy because .foo.com does not matche with foo.com' do
      @client.no_proxy = ".foo.com"
      @client.head("http://foo.com")
      @str.should =~ /CONNECT TO localhost/
    end
    it 'no proxy because foo.com matches with foo.com' do
      @client.no_proxy = "foo.com"
      @client.head("http://foo.com")
      @str.should =~ /CONNECT TO foo.com/
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
      @client.get("http://www.example.org/baz/foo").content.should == "hello"
      str.should match /^Cookie: foo=bar/
      str.should match /^Authorization: Basic YWRtaW46YWRtaW4=/
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
      @client.get("https://localhost:17171/baz").content.should == "hello"
    end
  end
  
  it "loopback response" do
    @client.test_loopback_response << "message body 1"
    @client.test_loopback_response << "message body 2"
    @client.get_content("http://somewhere").should == "message body 1"
    @client.get_content("http://somewhere").should == "message body 2"
    @client.debug_dev = str = ""
    @client.test_loopback_response << "message body 3"
    @client.get_content("http://somewhere").should == "message body 3"
    str.should match /message body 3/
  end
  
  it "loopback response stream" do
    @client.test_loopback_response << "message body 1"
    @client.test_loopback_response << "message body 2"
    conn = @client.get_async("http://somewhere")
    until conn.finished?
      Thread.pass
    end
    conn.pop.content.read.should == "message body 1"
    conn = @client.get_async("http://somewhere")
    until conn.finished?
      Thread.pass
    end
    conn.pop.content.read.should == "message body 2"
  end
  
  it "loopback http response" do
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
content-length: 100

message body 1"
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
content-length: 100

message body 2"
    @client.get_content("http://somewhere").should == "message body 1"
    @client.get_content("http://somewhere").should == "message body 2"
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
    res.content.should == "message body 1"
    res.header["x-foo"].should == ["XXX YYY"]
    res.header["x-bar"].should == ["XXX YYY"]
  end
  
  it "broken header" do
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
XXXXX
content-length: 100

message body 1"
    res = @client.get("http://somewhere")
    res.content.should == "message body 1"
  end
  
  it "request uri in response" do
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
content-length: 100

message body"
    @client.get("http://google.com/").header.request_uri.should == urify("http://google.com/")
  end
  
  it "request uri in response when redirect" do
    expected = urify(@srv.u("hello"))
    @client.get(@srv.u("redirect1"), :follow_redirect => true).header.request_uri.should == expected
    @client.get(@srv.u("redirect2"), :follow_redirect => true).header.request_uri.should == expected
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
      @client.get_content(@url).should eq 'hello'
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
    @client.post_content(@srv.u("redirect_see_other")).should == "hello"
  end
  
  it "redirect relative" do
    @client.test_loopback_http_response << "HTTP/1.0 302 OK\nLocation: hello\n\n"
    silent do
      @client.get_content(@srv.u('redirect1')).should eq 'hello'
    end

    @client.reset_all
    @client.redirect_uri_callback = @client.method(:strict_redirect_uri_callback)
    @client.get_content(@srv.u('redirect1')).should eq 'hello'
    @client.reset_all
    @client.test_loopback_http_response << "HTTP/1.0 302 OK\nLocation: hello\n\n"
    begin
      @client.get_content(@srv.u('redirect1'))
      false.should be_true
    rescue HTTPClient::BadResponseError => e
      e.res.status.should eq 302
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
      @client.get_content(https_url).should == "hello"
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
    @client.head(@srv.u("servlet")).header["x-head"][0].should == "head"
    param = {"1" => "2", "3" => "4"}
    res = @client.head(@srv.u("servlet"), param)
    params(res.header["x-query"][0]).should == param
  end
  
  it "head async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.head_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    params(res.header["x-query"][0]).should == param
  end
  
  it "get" do
    @client.get(@srv.u("servlet")).content.should == "get"
    param = {"1" => "2", "3" => "4"}
    res = @client.get(@srv.u("servlet"), param)
    params(res.header["x-query"][0]).should == param
    res.contenttype.should be_nil
    url = @srv.u("servlet?5=6&7=8")
    res = @client.get(url, param)
    params(res.header["x-query"][0]).should == param.merge("5" => "6", "7" => "8")
    res.contenttype.should be_nil
  end
  
  it "head follow redirect" do
    expected = urify(@srv.u("hello"))
    @client.head(@srv.u("hello"), :follow_redirect => true).header.request_uri.should == expected
    @client.head(@srv.u("redirect1"), :follow_redirect => true).header.request_uri.should == expected
    @client.head(@srv.u("redirect2"), :follow_redirect => true).header.request_uri.should == expected
  end
  
  it "get follow redirect" do
    @client.get(@srv.u("hello"), :follow_redirect => true).body.should == "hello"
    @client.get(@srv.u("redirect1"), :follow_redirect => true).body.should == "hello"
    @client.get(@srv.u("redirect2"), :follow_redirect => true).body.should == "hello"
  end
  
  it "get async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.get_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    params(res.header["x-query"][0]).should == param
  end
  
  it "get async for largebody" do
    conn = @client.get_async(@srv.u("largebody"))
    res = conn.pop
    res.content.read.length.should == 1000.*(1000)
  end
  
  it "get with block" do
    called = false
    res = @client.get(@srv.u("servlet")) do |str|
      str.should == "get"
      called = true
    end
    called.should be_true
    res.content.should be_nil
  end
  
  it "get with block chunk string recycle" do
    @client.read_block_size = 2
    body = []
    res = @client.get(@srv.u("servlet")) do |str|
      body << str
    end
    body.size.should == 2
    body.join.should == "get"
  end
  
  it "post" do
    @client.post(@srv.u("servlet")).content[0, 4].should == "post"
    param = {"1" => "2", "3" => "4"}
    res = @client.post(@srv.u("servlet"), param)
    params(res.header["x-query"][0]).should == param
  end
  
  it "post follow redirect" do
    @client.post(@srv.u("hello"), :follow_redirect => true).body.should == "hello"
    @client.post(@srv.u("redirect1"), :follow_redirect => true).body.should == "hello"
    @client.post(@srv.u("redirect2"), :follow_redirect => true).body.should == "hello"
  end
  
  it "post with content type" do
    param = [["1", "2"], ["3", "4"]]
    ext = {"content-type" => "application/x-www-form-urlencoded", "hello" => "world"}
    @client.post(@srv.u("servlet")).content[0, 4].should == "post"
    res = @client.post(@srv.u("servlet"), param, ext)
    params(res.header["x-query"][0]).should == Hash[param]
    ext = [["content-type", "multipart/form-data"], ["hello", "world"]]
    @client.post(@srv.u("servlet")).content[0, 4].should == "post"
    res = @client.post(@srv.u("servlet"), param, ext)
    res.content.should match /Content-Disposition: form-data; name="1"/
    res.content.should match /Content-Disposition: form-data; name="3"/
    ext = {"content-type" => "multipart/form-data; boundary=hello"}
    @client.post(@srv.u("servlet")).content[0, 4].should == "post"
    res = @client.post(@srv.u("servlet"), param, ext)
    res.content.should match /Content-Disposition: form-data; name="1"/
    res.content.should match /Content-Disposition: form-data; name="3"/
    res.content.should == "post,--hello\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n2\r\n--hello\r\nContent-Disposition: form-data; name=\"3\"\r\n\r\n4\r\n--hello--\r\n\r\n"
  end
  
  it "post with custom multipart and boolean params" do
    param = [["boolean_true", true]]
    ext = {"content-type" => "multipart/form-data"}
    @client.post(@srv.u("servlet")).content[0, 4].should == "post"
    res = @client.post(@srv.u("servlet"), param, ext)
    res.content.should match /Content-Disposition: form-data; name="boolean_true"\r\n\r\ntrue\r\n/

    param = [["boolean_false", false]]
    res = @client.post(@srv.u("servlet"), param, ext)
    res.content.should match /Content-Disposition: form-data; name="boolean_false"\r\n\r\nfalse\r\n/

    param = [["nil", nil]]
    res = @client.post(@srv.u("servlet"), param, ext)
    res.content.should match /Content-Disposition: form-data; name="nil"\r\n\r\n\r\n/
  end
  
  it "post with file" do
    STDOUT.sync = true
    File.open(__FILE__) do |file|
      res = @client.post(@srv.u("servlet"), 1 => 2, 3 => file)
      res.content.should match /^Content-Disposition: form-data; name="1"\r\n/mn
      res.content.should match /^Content-Disposition: form-data; name="3";/
      res.content.should match /FIND_TAG_IN_THIS_FILE/
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
    res.content.should match /\r\nContent-Disposition: form-data; name="1"\r\n/m
    res.content.should match /\r\n2\r\n/m
    res.content.should match /\r\nContent-Disposition: form-data; name="3"; filename=""\r\n/m
    str.string.should match /\r\nContent-Length:/m
    myio.called.should == 3
  end
  
  it "post with io nosize" do
    myio = StringIO.new("4")
    def myio.size
      nil
    end
    @client.debug_dev = str = StringIO.new
    res = @client.post(@srv.u("servlet"), {1 => 2, 3 => myio})
    res.content.should match /\r\nContent-Disposition: form-data; name="1"\r\n/m
    res.content.should match /\r\n2\r\n/m
    res.content.should match /\r\nContent-Disposition: form-data; name="3"; filename=""\r\n/m
    res.content.should match /\r\n4\r\n/m
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
    params(res.header["x-query"][0]).should == param
  end
  
  it "post with block" do
    called = false
    res = @client.post(@srv.u("servlet")) do |str|
      str.should == "post,"
      called = true
    end
    called.should be_true
    res.content.should be_nil
    called = false
    param = [["1", "2"], ["3", "4"]]
    res = @client.post(@srv.u("servlet"), param) do |str|
      str.should == "post,1=2&3=4"
      called = true
    end
    called.should be_true
    res.header["x-query"][0].should == "1=2&3=4"
    res.content.should be_nil
  end
  
  it "post with custom multipart" do
    ext = {"content-type" => "multipart/form-data"}
    @client.post(@srv.u("servlet")).content[0, 4].should == "post"
    body = [{ 'Content-Disposition' => 'form-data; name="1"', :content => "2"},
            { 'Content-Disposition' => 'form-data; name="3"', :content => "4"}]
    res = @client.post(@srv.u("servlet"), body, ext)
    res.content.should match /Content-Disposition: form-data; name="1"/
    res.content.should match /Content-Disposition: form-data; name="3"/
    ext = {"content-type" => "multipart/form-data; boundary=hello"}
    @client.post(@srv.u("servlet")).content[0, 4].should == "post"
    res = @client.post(@srv.u("servlet"), body, ext)
    res.content.should match /Content-Disposition: form-data; name="1"/
    res.content.should match /Content-Disposition: form-data; name="3"/
    res.content.should == "post,--hello\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n2\r\n--hello\r\nContent-Disposition: form-data; name=\"3\"\r\n\r\n4\r\n--hello--\r\n\r\n"
  end
  
  it "post with custom multipart and file" do
    STDOUT.sync = true
    File.open(__FILE__) do |file|
      ext = {"Content-Type" => "multipart/alternative"}
      body = [{"Content-Type" => "text/plain", :content => "this is only a test"}, {"Content-Type" => "application/x-ruby", :content => file}]
      res = @client.post(@srv.u("servlet"), body, ext)
      res.content.should match /^Content-Type: text\/plain\r\n/m
      res.content.should match /^this is only a test\r\n/m
      res.content.should match /^Content-Type: application\/x-ruby\r\n/m
      res.content.should match /FIND_TAG_IN_THIS_FILE/
    end
  end
  
  it "put" do
    @client.put(@srv.u("servlet")).content.should == "put"
    param = {"1" => "2", "3" => "4"}
    @client.debug_dev = str = ""
    res = @client.put(@srv.u("servlet"), param)
    params(res.header["x-query"][0]).should == param
    str.split(/\r?\n/)[5].should == "Content-Type: application/x-www-form-urlencoded"
  end
  
  it "put bytesize" do
    res = @client.put(@srv.u("servlet"), "txt" => "あいうえお")
    res.header["x-query"][0].should == "txt=%E3%81%82%E3%81%84%E3%81%86%E3%81%88%E3%81%8A"
    res.header["x-size"][0].should == "15"
  end
  
  it "put async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.put_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    params(res.header["x-query"][0]).should == param
  end
  
  it "patch" do
    @client.patch(@srv.u("servlet")).content.should == "patch"
    param = {"1" => "2", "3" => "4"}
    @client.debug_dev = str = ""
    res = @client.patch(@srv.u("servlet"), param)
    params(res.header["x-query"][0]).should == param
    str.split(/\r?\n/)[5].should == "Content-Type: application/x-www-form-urlencoded"
  end
  
  it "patch async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.patch_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    params(res.header["x-query"][0]).should == param
  end
  
  it "delete" do
    @client.delete(@srv.u("servlet")).content.should == "delete"
  end
  
  it "delete with body" do
    param = {'1'=>'2', '3'=>'4'}
    @client.debug_dev = str = ''
    @client.delete(@srv.u('servlet'), param).content.should eq "delete"
    HTTP::Message.parse(str.split(/\r?\n\r?\n/)[2]).should eq({'1' => ['2'], '3' => ['4']})
  end
  
  it "delete async" do
    conn = @client.delete_async(@srv.u("servlet"))
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    res.content.read.should == "delete"
  end
  
  it "options" do
    @client.options(@srv.u("servlet")).content.should == "options"
  end
  
  it "options async" do
    conn = @client.options_async(@srv.u("servlet"))
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    res.content.read.should == "options"
  end
  
  it "propfind" do
    @client.propfind(@srv.u("servlet")).content.should == "propfind"
  end
  
  it "propfind async" do
    conn = @client.propfind_async(@srv.u("servlet"))
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    res.content.read.should == "propfind"
  end
  
  it "proppatch" do
    @client.proppatch(@srv.u("servlet")).content.should == "proppatch"
    param = {"1" => "2", "3" => "4"}
    res = @client.proppatch(@srv.u("servlet"), param)
    res.content.should == "proppatch"
    params(res.header["x-query"][0]).should == param
  end
  
  it "proppatch async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.proppatch_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    res.content.read.should == "proppatch"
    params(res.header["x-query"][0]).should == param
  end
  
  it "trace" do
    @client.trace(@srv.u("servlet")).content.should == "trace"
    param = {"1" => "2", "3" => "4"}
    res = @client.trace(@srv.u("servlet"), param)
    params(res.header["x-query"][0]).should == param
  end
  
  it "trace async" do
    param = {"1" => "2", "3" => "4"}
    conn = @client.trace_async(@srv.u("servlet"), param)
    until conn.finished?
      Thread.pass
    end
    res = conn.pop
    params(res.header["x-query"][0]).should == param
  end
  
  it "chunked" do
    @client.get_content(@srv.u("chunked"), "msg" => "chunked").should == "chunked"
    @client.get_content(@srv.u("chunked"), "msg" => "あいうえお").should == "あいうえお"
  end
  
  it "chunked empty" do
    @client.get_content(@srv.u("chunked"), "msg" => "").should == ""
  end
  
  it "get query" do
    check_query_get({1=>2}).should eq({'1'=>'2'})
    check_query_get({"a"=>"A", "B"=>"b"}).should eq({'a'=>'A', 'B'=>'b'})
    check_query_get({"&"=>"&"}).should eq({'&'=>'&'})
    check_query_get({"= "=>" =+"}).should eq({'= '=>' =+'})
    ['=', '&'].sort.should eq check_query_get([["=", "="], ["=", "&"]])['='].to_ary.sort

    {'123'=>'45'}.should eq check_query_get('123=45')
    {'12 3'=>'45', ' '=>' '}.should eq check_query_get('12+3=45&+=+')
    {}.should eq check_query_get('')
    {'1'=>'2'}.should eq check_query_get({1=>StringIO.new('2')})
    {'1'=>'2', '3'=>'4'}.should eq check_query_get(StringIO.new('3=4&1=2'))

    hash = check_query_get({"a"=>["A","a"], "B"=>"b"})
    {'a'=>'A', 'B'=>'b'}.should eq hash
    ['A','a'].should eq hash['a'].to_ary

    hash = check_query_get({"a"=>WEBrick::HTTPUtils::FormData.new("A","a"), "B"=>"b"})
    {'a'=>'A', 'B'=>'b'}.should eq hash
    ['A','a'].should eq hash['a'].to_ary

    hash = check_query_get({"a"=>[StringIO.new("A"),StringIO.new("a")], "B"=>StringIO.new("b")})
    {'a'=>'A', 'B'=>'b'}.should eq hash
    ['A','a'].should eq hash['a'].to_ary
  end
  
  it "post body" do
    check_query_post(1 => 2).should == {"1" => "2"}
    check_query_post("a" => "A", "B" => "b").should == {"a" => "A", "B" => "b"}
    check_query_post("&" => "&").should == {"&" => "&"}
    check_query_post("= " => " =+").should == {"= " => " =+"}
    check_query_post([["=", "="], ["=", "&"]])["="].to_ary.sort.should == ["=", "&"].sort
    check_query_post("123=45").should == {"123" => "45"}
    check_query_post("12+3=45&+=+").should == {"12 3" => "45", " " => " "}
    check_query_post("").should == {}
    post_body = StringIO.new("foo=bar&foo=baz")
    check_query_post(post_body)["foo"].to_ary.sort.should == ["bar", "baz"]
  end
  
  it "extra headers" do
    str = ""
    @client.debug_dev = str
    @client.head(@srv.u, nil, "ABC" => "DEF")
    lines = str.split(/(?:\r?\n)+/)
    lines[0].should == "= Request"
    lines[4].should match "ABC: DEF"
    str = ""
    @client.debug_dev = str
    @client.get(@srv.u, nil, [["ABC", "DEF"], ["ABC", "DEF"]])
    lines = str.split(/(?:\r?\n)+/)
    lines[0].should == "= Request"
    lines[4].should match "ABC: DEF"
    lines[5].should match "ABC: DEF"
  end
  
  it "http custom date header" do
    @client.debug_dev = str = ""
    res = @client.get(@srv.u("hello"), :header => {"Date" => "foo"})
    lines = str.split(/(?:\r?\n)+/)
    lines[4].should == "Date: foo"
  end
  
  it "timeout" do
    @client.connect_timeout.should == 60
    @client.send_timeout.should == 120
    @client.receive_timeout.should == 60
    @client.connect_timeout = 1
    @client.send_timeout = 2
    @client.receive_timeout = 3
    @client.connect_timeout.should == 1
    @client.send_timeout.should == 2
    @client.receive_timeout.should == 3
  end
  
  it "connect timeout" do
    
  end
  
  it "send timeout" do
    
  end
  
  it "receive timeout" do
    @client.get_content(@srv.u("sleep?sec=2")).should == "hello"
    @client.receive_timeout = 1
    @client.get_content(@srv.u("sleep?sec=0")).should == "hello"
    
    expect {
      @client.get_content(@srv.u("sleep?sec=2"))
    }.to raise_error(HTTPClient::ReceiveTimeoutError)
    @client.receive_timeout = 3
    @client.get_content(@srv.u("sleep?sec=2")).should == "hello"
  end
  
  it "receive timeout post" do
    @client.post(@srv.u("sleep"), :sec => 2).content.should == "hello"
    @client.receive_timeout = 1
    @client.post(@srv.u("sleep"), :sec => 0).content.should == "hello"
    
    expect {
      @client.post(@srv.u("sleep"), :sec => 2)\
    }.to raise_error(HTTPClient::ReceiveTimeoutError)

    @client.receive_timeout = 3
    @client.post(@srv.u("sleep"), :sec => 2).content.should == "hello"
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
    cookie.domain_match(url.host, cookie.domain).should be_true
    @client.reset_all
    @client.test_loopback_http_response << "HTTP/1.0 200 OK
Set-Cookie: foo=bar; expires=#{Time.at(1924873200).gmtime.httpdate}

OK"
    @client.get_content("http://rubyforge.org/account/login.php")
    @client.save_cookie_store
    str = File.read(cookiefile)
    str.should match /http:\/\/rubyforge.org\/account\/login.php\tfoo\tbar\t1924873200\trubyforge.org\t\/account\t1/
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
    c.finished?.should be_true
    c.join.should be_nil
  end
  
  it "site" do
    site = HTTPClient::Site.new
    site.scheme.should == "tcp"
    site.host.should == "0.0.0.0"
    site.port.should == 0
    site.addr.should == "tcp://0.0.0.0:0"
    site.to_s.should == "tcp://0.0.0.0:0"
    
    site.inspect
    site = HTTPClient::Site.new(urify("http://localhost:12345/foo"))
    site.scheme.should == "http"
    site.host.should == "localhost"
    site.port.should == 12345
    site.addr.should == "http://localhost:12345"
    site.to_s.should == "http://localhost:12345"
    
    site.inspect
    site1 = HTTPClient::Site.new(urify("http://localhost:12341/"))
    site2 = HTTPClient::Site.new(urify("http://localhost:12342/"))
    site3 = HTTPClient::Site.new(urify("http://localhost:12342/"))
    site1.should_not == site2
    h = {site1 => "site1", site2 => "site2"}
    h[site3] = "site3"
    h[site1].should == "site1"
    h[site2].should == "site3"
  end
  
  it "http header" do
    res = @client.get(@srv.u("hello"))
    res.contenttype.should == "text/html"
    res.header.get(nil).size.should == 5
    res.header.delete("connection")
    res.header.get(nil).size.should == 4
    res.header["foo"] = "bar"
    res.header["foo"].should == ["bar"]
    res.header.get("foo").should == [["foo", "bar"]]
    res.header["foo"] = ["bar", "bar2"]
    res.header.get("foo").should == [["foo", "bar"], ["foo", "bar2"]]
  end
  
  it "session manager" do
    mgr = HTTPClient::SessionManager.new(@client)
    (mgr.instance_eval do
      @proxy
    end).should be_nil
    mgr.debug_dev.should be_nil
    @client.debug_dev = Object.new
    @client.proxy = "http://myproxy:12345"
    mgr = HTTPClient::SessionManager.new(@client)
    mgr.instance_eval do
      @proxy
    end.to_s.should == "http://myproxy:12345"
    mgr.debug_dev.should == @client.debug_dev
  end
  
  it "socket local" do
    @client.socket_local.host = '127.0.0.1'
    @client.get_content(@srv.u('hello')).should == 'hello'
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
    HTTP::Message.escape_query(ary).should == "key2=b&key2=c&key2=d&key1=a&key3=z"
  end
  it 'charset' do
    body = @client.get(@srv.u("charset")).body
    body.encoding.should == Encoding::EUC_JP
    body.should == "あいうえお".encode(Encoding::EUC_JP)
  end
  it 'continue' do
    @client.debug_dev = str = ''
    res = @client.get(@srv.u('continue'), :header => {:Expect => '100-continue'})
    res.status.should eq 200
    res.body.should eq 'done!'
    str.should match /Expect: 100-continue/
  end

  it 'ipv6' do
    server = TCPServer.open('::1', 0) rescue return # Skip if IPv6 is unavailable.
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
      @client.get(uri).body.should eq '12345'
    ensure
      server.close
      server_thread.kill
      server_thread.join
    end
  end
end
