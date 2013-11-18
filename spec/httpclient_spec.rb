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
end
