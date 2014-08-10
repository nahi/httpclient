# coding: utf-8
require 'spec_helper'

describe HTTPClient do
  before :each do
    @client = HTTPClient.new
  end

  describe 'GET' do
    it 'performs normal GET' do
      HTTPClient.new.get(@srv.u('servlet')) do |s|
        expect(s).to eq 'get'
      end
    end
    
    it 'raises if bad URI' do
      expect { HTTPClient.get_content '/z/' }.to raise_error(HTTPClient::BadURIError)
    end
    
    describe '#download_file' do
      it 'writes to file' do
        file = Tempfile.new('httpcl')
        HTTPClient.new.download_file(@srv.u('largebody'), file.path)
        expect(file.read.length).to eq 1_000_000
      end

      it 'compressed' do
        file = Tempfile.new('httpcl')
        @client.download_file(@srv.u('compressed?enc=gzip'), file.path)
        expect(file.read.length).to eq 25
      end

      it 'compressed transparent' do
        @client.transparent_gzip_decompression = true

        file = Tempfile.new('httpcl')
        @client.download_file(@srv.u('compressed?enc=gzip'), file.path)
        cnt = file.read
        expect(cnt.length).to eq 5
        expect(cnt).to eq 'hello'

        @client.download_file(@srv.u('compressed?enc=deflate'), file.path)
        cnt = file.read
        expect(cnt.length).to eq 5
        expect(cnt).to eq 'hello'
      end

      it 'compressed large' do
        file = Tempfile.new('httpcl')
        @client.transparent_gzip_decompression = true

        content = @client.download_file(@srv.u('compressed_large?enc=gzip'), file.path)
        expect(file.read).to eq LARGE_STR

        content = @client.download_file(@srv.u('compressed_large?enc=deflate'), file.path)
        expect(file.read).to eq LARGE_STR
      end
    end

    describe '#get_content' do
      it 'normal' do
        expect(@client.get_content(@srv.u('hello'))).to eq 'hello'
        expect(@client.get_content(@srv.u('redirect1'))).to eq 'hello'
        expect(@client.get_content(@srv.u('redirect2'))).to eq 'hello'
      end

      it '127.0.0.1' do
        url = @srv.u.sub(/localhost/, '127.0.0.1')
        expect(@client.get_content(url + 'hello')).to eq 'hello'
        expect(@client.get_content(url + 'redirect1')).to eq 'hello'
        expect(@client.get_content(url + 'redirect2')).to eq 'hello'
      end

      it 'redirect callback' do
        called = false
        @client.redirect_uri_callback = lambda { |uri, res|
          newuri = res.header['location'][0]
          called = true
          newuri
        }

        expect(@client.get_content(@srv.u('relative_redirect'))).to eq 'hello'
        expect(called).to be_truthy
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
          expect(str).to eq 'hello' 
        end
        @client.get_content(@srv.u + 'redirect1') do |str|
          expect(str).to eq 'hello' 
        end
        @client.get_content(@srv.u + 'redirect2') do |str|
          expect(str).to eq 'hello' 
        end
      end

      it 'compressed' do
        @client.transparent_gzip_decompression = false

        content = @client.get_content(@srv.u 'compressed?enc=gzip')
        expect(content).not_to eq 'hello'
        expect(content).to eq GZIP_CONTENT
        @client.transparent_gzip_decompression = true

        content = @client.get_content(@srv.u 'compressed?enc=gzip')
        expect(content).to eq 'hello'

        content = @client.get_content(@srv.u 'compressed?enc=deflate')
        expect(content).to eq 'hello'
      end

      it 'compressed large' do
        @client.transparent_gzip_decompression = true

        content = @client.get_content(@srv.u 'compressed_large?enc=gzip')
        expect(content).to eq LARGE_STR

        content = @client.get_content(@srv.u 'compressed_large?enc=deflate')
        expect(content).to eq LARGE_STR
      end
    end
  end
  describe 'request' do
    describe 'get with block' do
      it 'works with filter_block: true' do
        @client.request(:get, @srv.u('hello')) do |str|
          expect(str).to eq 'hello' 
        end
      end
      it 'works with filter_block: false' do
        @client.request(:get, @srv.u('hello'), filter_block: false) do |req, str|
          expect(req.class.name).to eq 'HTTP::Message' 
          expect(str).to eq 'hello' 
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
      expect(lines[0]).to eq '= Request'
      expect(lines[4]).to eq "User-Agent: HTTPClient #{HTTPClient::VERSION}"
    end

    it 'custom' do
      client = HTTPClient.new(nil, "agent_name_foo")
      str = ""
      client.debug_dev = str
      client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      expect(lines[0]).to eq '= Request'
      expect(lines[4]).to eq 'User-Agent: agent_name_foo'
    end
  end

  describe 'protocol versions' do
    it '0.9' do
      @client.protocol_version = 'HTTP/0.9'
      @client.debug_dev = str = ''
      @client.test_loopback_http_response << "hello\nworld\n"
      res = @client.get(@srv.u 'hello')
      expect(res.http_version).to eq '0.9' 
      expect(res.status).to be_nil 
      expect(res.reason).to be_nil 
      expect(res.content).to eq "hello\nworld\n" 
      lines = str.split(/(?:\r?\n)+/)
      expect(lines[0]).to eq "= Request" 
      expect(lines[2]).to eq "! CONNECTION ESTABLISHED" 
      expect(lines[3]).to eq "GET /hello HTTP/0.9" 
      expect(lines[7]).to eq "Connection: close" 
      expect(lines[8]).to eq "= Response" 
      expect(lines[9]).to match /^hello$/ 
      expect(lines[10]).to match /^world$/ 
    end

    it '1.0' do
      expect(@client.protocol_version).to be_nil 
      @client.protocol_version = 'HTTP/1.0'
      expect(@client.protocol_version).to eq 'HTTP/1.0' 
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u 'hello')
      lines = str.split(/(?:\r?\n)+/)
      expect(lines[0]).to eq "= Request"
      expect(lines[2]).to eq "! CONNECTION ESTABLISHED"
      expect(lines[3]).to eq "GET /hello HTTP/1.0"
      expect(lines[7]).to eq "Connection: close"
      expect(lines[8]).to eq "= Response"
    end

    it '1.1' do
      expect(@client.protocol_version).to be_nil 
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      expect(lines[0]).to eq "= Request" 
      expect(lines[2]).to eq "! CONNECTION ESTABLISHED" 
      expect(lines[3]).to eq "GET / HTTP/1.1" 
      expect(lines[7]).to eq "Host: localhost:#{@srv.port}" 
      @client.protocol_version = 'HTTP/1.1'
      expect(@client.protocol_version).to eq 'HTTP/1.1' 
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      expect(lines[0]).to eq "= Request" 
      expect(lines[2]).to eq "! CONNECTION ESTABLISHED" 
      expect(lines[3]).to eq "GET / HTTP/1.1" 
      @client.protocol_version = 'HTTP/1.0'
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      expect(lines[0]).to eq "= Request" 
      expect(lines[2]).to eq "! CONNECTION ESTABLISHED" 
      expect(lines[3]).to eq "GET / HTTP/1.0" 
    end
  end

  describe 'accept' do
    it '*/* by default' do
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u)
      lines = str.split(/(?:\r?\n)+/)
      expect(lines[5]).to eq "Accept: */*" 
    end

    it 'sets properly' do
      str = ""
      @client.debug_dev = str
      @client.get(@srv.u, :header => {:Accept => 'text/html'})
      lines = str.split(/(?:\r?\n)+/)
      expect(lines[4]).to eq "Accept: text/html" 
      lines.each do |line|
        expect(line).not_to eq "Accept: */*" 
      end
    end
  end

  describe 'POST' do
    describe '#post_content' do
      it 'works' do
        expect(@client.post_content(@srv.u('hello'))).to eq 'hello'
        expect(@client.post_content(@srv.u("redirect1"))).to eq 'hello'
        expect(@client.post_content(@srv.u("redirect2"))).to eq 'hello'
      end
    end

    it 'redirect callback' do
      called = false
      @client.redirect_uri_callback = lambda { |uri, res|
        newuri = res.header['location'][0]
        called = true
        newuri
      }
      expect(@client.post_content(@srv.u("relative_redirect"))).to eq 'hello'
      expect(called).to be_truthy
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
        expect(@client.post_content(@srv.u("servlet"), post_body)).to eq 'post,1234567890'

        # all browsers use GET for 302
        post_body = StringIO.new("1234567890")
        expect(@client.post_content(@srv.u("servlet_413"), post_body)).to eq '1234567890' 

        expect(@client.get_content(@srv.u("servlet_redirect_413"))).to eq ''

        post_body = StringIO.new("1234567890")
        expect(@client.post_content(@srv.u("servlet_redirect_413"), post_body)).to eq ''

        post_body = StringIO.new("1234567890")
        expect(@client.post_content(@srv.u("servlet_temporary_redirect"), post_body)).to eq 'post,1234567890'

        post_body = StringIO.new("1234567890")
        expect(@client.post_content(@srv.u("servlet_see_other"), post_body)).to eq 'get'
      end

      it 'doesnt rewind' do
        post_body = StringIO.new("1234567890")
        post_body.read(5)
        expect(@client.post_content(@srv.u("servlet_temporary_redirect"), post_body)).to eq 'post,67890' 
      end
    end
  end

  describe 'util' do
    it '#urify' do
      expect(urify(nil)).to be_nil
      uri = 'http://foo'
      # urify(uri).class.name.should eq 'HTTPClient::Util::AddressableURI'
      expect(urify(uri)).to eq urify(uri)
      expect(urify(uri).to_s).to eq uri
      expect(urify(urify(uri))).to eq urify(uri)
    end
  end
end
