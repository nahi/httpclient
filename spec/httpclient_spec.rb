# coding: utf-8
require 'spec_helper'

describe HTTPClient do
  before :each do
    @client = HTTPClient.new
  end

  describe 'GET' do
    it 'performs normal GET' do
      HTTPClient.new.get(@srv.u('servlet')) do |s|
        s.should eq 'get'
      end
    end
    
    describe '#download_file' do
      it 'writes to file' do
        file = Tempfile.new('httpcl')
        HTTPClient.new.download_file(@srv.u('largebody'), file.path)
        file.read.length.should eq 1_000_000
      end

      it 'compressed' do
        file = Tempfile.new('httpcl')
        @client.download_file(@srv.u('compressed?enc=gzip'), file.path)
        file.read.length.should eq 25
      end

      it 'compressed transparent' do
        @client.transparent_gzip_decompression = true

        file = Tempfile.new('httpcl')
        @client.download_file(@srv.u('compressed?enc=gzip'), file.path)
        cnt = file.read
        cnt.length.should eq 5
        cnt.should eq 'hello'

        @client.download_file(@srv.u('compressed?enc=deflate'), file.path)
        cnt = file.read
        cnt.length.should eq 5
        cnt.should eq 'hello'
      end

      it 'compressed large' do
        file = Tempfile.new('httpcl')
        @client.transparent_gzip_decompression = true

        content = @client.download_file(@srv.u('compressed_large?enc=gzip'), file.path)
        file.read.should eq LARGE_STR

        content = @client.download_file(@srv.u('compressed_large?enc=deflate'), file.path)
        file.read.should eq LARGE_STR
      end
    end

    describe '#get_content' do
      it 'normal' do
        @client.get_content(@srv.u('hello')).should eq 'hello'
        @client.get_content(@srv.u('redirect1')).should eq 'hello'
        @client.get_content(@srv.u('redirect2')).should eq 'hello'
      end

      it '127.0.0.1' do
        url = @srv.u.sub(/localhost/, '127.0.0.1')
        @client.get_content(url + 'hello').should eq 'hello'
        @client.get_content(url + 'redirect1').should eq 'hello'
        @client.get_content(url + 'redirect2').should eq 'hello'
      end

      it 'redirect callback' do
        called = false
        @client.redirect_uri_callback = lambda { |uri, res|
          newuri = res.header['location'][0]
          called = true
          newuri
        }

        @client.get_content(@srv.u('relative_redirect')).should eq 'hello'
        called.should be_true
      end

      it 'errors' do
        expect {
          @client.get_content(@srv.u 'notfound')
        }.to raise_error(HTTPClient::BadResponseError)

        expect {
          @client.get_content(@srv.u 'redirect_self')
        }.to raise_error(HTTPClient::BadResponseError)
      end

      it 'with block' do
        @client.get_content(@srv.u 'hello') do |str|
          str.should eq 'hello' 
        end
        @client.get_content(@srv.u + 'redirect1') do |str|
          str.should eq 'hello' 
        end
        @client.get_content(@srv.u + 'redirect2') do |str|
          str.should eq 'hello' 
        end
      end

      it 'compressed' do
        @client.transparent_gzip_decompression = false

        content = @client.get_content(@srv.u 'compressed?enc=gzip')
        content.should_not eq 'hello'
        content.should eq GZIP_CONTENT
        @client.transparent_gzip_decompression = true

        content = @client.get_content(@srv.u 'compressed?enc=gzip')
        content.should eq 'hello'

        content = @client.get_content(@srv.u 'compressed?enc=deflate')
        content.should eq 'hello'
      end

      it 'compressed large' do
        @client.transparent_gzip_decompression = true

        content = @client.get_content(@srv.u 'compressed_large?enc=gzip')
        content.should eq LARGE_STR

        content = @client.get_content(@srv.u 'compressed_large?enc=deflate')
        content.should eq LARGE_STR
      end
    end
  end
  describe 'request' do
    describe 'get with block' do
      it 'works with filter_block: true' do
        @client.request(:get, @srv.u('hello')) do |str|
          str.should eq 'hello' 
        end
      end
      it 'works with filter_block: false' do
        @client.request(:get, @srv.u('hello'), filter_block: false) do |req, str|
          req.class.name.should eq 'HTTP::Message' 
          str.should eq 'hello' 
        end
      end
    end
  end
  describe 'agent name' do
    it 'default' do
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      lines[0].should eq '= Request'
      lines[4].should eq "User-Agent: HTTPClient #{HTTPClient::VERSION}"
    end

    it 'custom' do
      client = HTTPClient.new(nil, "agent_name_foo")
      str = ""
      client.debug_dev = str
      client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      lines[0].should eq '= Request'
      lines[4].should eq 'User-Agent: agent_name_foo'
    end
  end

  describe 'protocol versions' do
    it '0.9' do
      @client.protocol_version = 'HTTP/0.9'
      @client.debug_dev = str = ''
      @client.test_loopback_http_response << "hello\nworld\n"
      res = @client.get(@srv.u 'hello')
      res.http_version.should eq '0.9' 
      res.status.should be_nil 
      res.reason.should be_nil 
      res.content.should eq "hello\nworld\n" 
      lines = str.split(/(?:\r?\n)+/)
      lines[0].should eq "= Request" 
      lines[2].should eq "! CONNECTION ESTABLISHED" 
      lines[3].should eq "GET /hello HTTP/0.9" 
      lines[7].should eq "Connection: close" 
      lines[8].should eq "= Response" 
      lines[9].should match /^hello$/ 
      lines[10].should match /^world$/ 
    end

    it '1.0' do
      @client.protocol_version.should be_nil 
      @client.protocol_version = 'HTTP/1.0'
      @client.protocol_version.should eq 'HTTP/1.0' 
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u 'hello')
      lines = str.split(/(?:\r?\n)+/)
      lines[0].should eq "= Request"
      lines[2].should eq "! CONNECTION ESTABLISHED"
      lines[3].should eq "GET /hello HTTP/1.0"
      lines[7].should eq "Connection: close"
      lines[8].should eq "= Response"
    end

    it '1.1' do
      @client.protocol_version.should be_nil 
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      lines[0].should eq "= Request" 
      lines[2].should eq "! CONNECTION ESTABLISHED" 
      lines[3].should eq "GET / HTTP/1.1" 
      lines[7].should eq "Host: localhost:#{@srv.port}" 
      @client.protocol_version = 'HTTP/1.1'
      @client.protocol_version.should eq 'HTTP/1.1' 
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      lines[0].should eq "= Request" 
      lines[2].should eq "! CONNECTION ESTABLISHED" 
      lines[3].should eq "GET / HTTP/1.1" 
      @client.protocol_version = 'HTTP/1.0'
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      lines[0].should eq "= Request" 
      lines[2].should eq "! CONNECTION ESTABLISHED" 
      lines[3].should eq "GET / HTTP/1.0" 
    end
  end

  describe 'accept' do
    it '*/* by default' do
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      lines[5].should eq "Accept: */*" 
    end

    it 'sets properly' do
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u, :header => {:Accept => 'text/html'})
      lines = str.split(/(?:\r?\n)+/)
      lines[4].should eq "Accept: text/html" 
      lines.each do |line|
        line.should_not eq "Accept: */*" 
      end
    end
  end

  describe 'POST' do
    describe '#post_content' do
      it 'works' do
        @client.post_content(@srv.u('hello')).should eq 'hello'
        @client.post_content(@srv.u("redirect1")).should eq 'hello'
        @client.post_content(@srv.u("redirect2")).should eq 'hello'
      end
    end

    it 'redirect callback' do
      called = false
      @client.redirect_uri_callback = lambda { |uri, res|
        newuri = res.header['location'][0]
        called = true
        newuri
      }
      @client.post_content(@srv.u("relative_redirect")).should eq 'hello'
      called.should be_true
    end

    it 'errors' do
      expect {
        @client.post_content(@srv.u 'notfound')
      }.to raise_error(HTTPClient::BadResponseError)

      expect {
        @client.post_content(@srv.u 'redirect_self')
      }.to raise_error(HTTPClient::BadResponseError)
    end


    describe 'string io' do
      it do
        post_body = StringIO.new("1234567890")
        @client.post_content(@srv.u("servlet"), post_body).should eq 'post,1234567890'

        # all browsers use GET for 302
        post_body = StringIO.new("1234567890")
        @client.post_content(@srv.u("servlet_413"), post_body).should eq '1234567890' 

        @client.get_content(@srv.u("servlet_redirect_413")).should eq ''

        post_body = StringIO.new("1234567890")
        @client.post_content(@srv.u("servlet_redirect_413"), post_body).should eq ''

        post_body = StringIO.new("1234567890")
        @client.post_content(@srv.u("servlet_temporary_redirect"), post_body).should eq 'post,1234567890'

        post_body = StringIO.new("1234567890")
        @client.post_content(@srv.u("servlet_see_other"), post_body).should eq 'get'
      end

      it 'doesnt rewind' do
        post_body = StringIO.new("1234567890")
        post_body.read(5)
        @client.post_content(@srv.u("servlet_temporary_redirect"), post_body).should eq 'post,67890' 
      end
    end
  end

  describe 'util' do
    it '#urify' do
      urify(nil).should be_nil
      uri = 'http://foo'
      urify(uri).class.name.should eq 'URI::HTTP'
      urify(uri).should eq urify(uri)
      urify(uri).to_s.should eq uri
      urify(urify(uri)).should eq urify(uri)
    end
  end
end
