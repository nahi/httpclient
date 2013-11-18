# coding: utf-8
require 'spec_helper'

describe HTTPClient do
  before :all do
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

        @client.transparent_gzip_decompression = false
      end

      it 'compressed large' do
        file = Tempfile.new('httpcl')
        @client.transparent_gzip_decompression = true

        content = @client.download_file(@srv.u('compressed_large?enc=gzip'), file.path)
        file.read.should eq LARGE_STR

        content = @client.download_file(@srv.u('compressed_large?enc=deflate'), file.path)
        file.read.should eq LARGE_STR

        @client.transparent_gzip_decompression = false
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

        @client.transparent_gzip_decompression = false
      end

      it 'compressed large' do
        @client.transparent_gzip_decompression = true

        content = @client.get_content(@srv.u 'compressed_large?enc=gzip')
        content.should eq LARGE_STR

        content = @client.get_content(@srv.u 'compressed_large?enc=deflate')
        content.should eq LARGE_STR

        @client.transparent_gzip_decompression = false
      end
    end
  end
end
