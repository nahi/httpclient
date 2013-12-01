# coding: utf-8
require 'spec_helper'

describe HTTP::Message do
  it 'has sane defaults for mime handlers' do
    HTTP::Message.get_mime_type_func.should be_nil
    HTTP::Message.mime_type_handler.should be_nil
  end

  context 'reset' do
    before :each do
      HTTP::Message.set_mime_type_func(nil)
      HTTP::Message.mime_type_handler = nil
    end
    it 'mime type' do
      HTTP::Message.mime_type('foo.txt').should eq 'text/plain'
      HTTP::Message.mime_type('foo.html').should eq 'text/html'
      HTTP::Message.mime_type('foo.htm').should eq 'text/html'
      HTTP::Message.mime_type('foo.doc').should eq 'application/msword'
      HTTP::Message.mime_type('foo.png').should eq 'image/png'
      HTTP::Message.mime_type('foo.gif').should eq 'image/gif'
      HTTP::Message.mime_type('foo.jpg').should eq 'image/jpeg'
      HTTP::Message.mime_type('foo.jpeg').should eq 'image/jpeg'
      HTTP::Message.mime_type('foo.unknown').should eq 'application/octet-stream'
    end

    it 'mime handler' do
      handler = lambda { |path| 'hello/world' }
      HTTP::Message.mime_type_handler = handler
      HTTP::Message.mime_type_handler.should_not be_nil

      HTTP::Message.get_mime_type_func.should_not be_nil

      HTTP::Message.mime_type('foo.txt').should eq 'hello/world'

      HTTP::Message.mime_type_handler = nil
      HTTP::Message.mime_type('foo.txt').should eq 'text/plain'
      HTTP::Message.set_mime_type_func(nil)
      HTTP::Message.mime_type('foo.txt').should eq 'text/plain'

      handler = lambda { |path| nil }
      HTTP::Message.mime_type_handler = handler
      HTTP::Message.mime_type('foo.txt').should eq 'application/octet-stream'
    end
  end


  it 'connect request' do
    req = HTTP::Message.new_connect_request(urify('https://foo/bar'))
    req.dump.should eq "CONNECT foo:443 HTTP/1.0\r\n\r\n" 
    req = HTTP::Message.new_connect_request(urify('https://example.com/'))
    req.dump.should eq "CONNECT example.com:443 HTTP/1.0\r\n\r\n" 
  end

  it 'response' do
    res = HTTP::Message.new_response('response')
    res.contenttype = 'text/plain'
    res.header.body_date = Time.at(946652400)
    [
      "",
      "Content-Length: 8",
      "Content-Type: text/plain",
      "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
      "Status: 200 OK",
      "response"
    ].should eq res.dump.split(/\r\n/).sort

    res.header['Content-Length'].should eq ['8']
    res.headers['Content-Length'].should eq '8'
    res.header.set('foo', 'bar')
    [
      "",
      "Content-Length: 8",
      "Content-Type: text/plain",
      "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
      "Status: 200 OK",
      "foo: bar",
      "response"
    ].should eq res.dump.split(/\r\n/).sort

    res = HTTP::Message.new_response(nil)
    [
      "Content-Length: 0",
      "Content-Type: text/html; charset=us-ascii",
      "Status: 200 OK"
    ].should eq res.dump.split(/\r\n/).sort
  end

  it 'response cookies' do
    res = HTTP::Message.new_response('response')
    res.contenttype = 'text/plain'
    res.header.body_date = Time.at(946652400)
    res.cookies.should be_nil
    res.header['Set-Cookie'] = [
      'CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT',
      'PART_NUMBER=ROCKET_LAUNCHER_0001; path=/'
    ]
    [
      "",
      "Content-Length: 8",
      "Content-Type: text/plain",
      "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
      "Set-Cookie: CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT",
      "Set-Cookie: PART_NUMBER=ROCKET_LAUNCHER_0001; path=/",
      "Status: 200 OK",
      "response"
    ].should eq res.dump.split(/\r\n/).sort
    
    res.cookies.size.should eq 2 
    res.cookies[0].name.should eq 'CUSTOMER' 
    res.cookies[1].name.should eq 'PART_NUMBER' 
  end

  it '#ok?' do
    res = HTTP::Message.new_response('response')
    res.ok?.should eq true 
    res.status = 404
    res.ok?.should eq false 
    res.status = 500
    res.ok?.should eq false 
    res.status = 302
    res.ok?.should eq false 
  end
end
