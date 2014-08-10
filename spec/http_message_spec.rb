# coding: utf-8
require 'spec_helper'

describe HTTP::Message do
  it 'has sane defaults for mime handlers' do
    expect(HTTP::Message.get_mime_type_func).to be_nil
    expect(HTTP::Message.mime_type_handler).to be_nil
  end

  context 'reset' do
    before :each do
      HTTP::Message.set_mime_type_func(nil)
      HTTP::Message.mime_type_handler = nil
    end
    it 'mime type' do
      expect(HTTP::Message.mime_type('foo.txt')).to eq 'text/plain'
      expect(HTTP::Message.mime_type('foo.html')).to eq 'text/html'
      expect(HTTP::Message.mime_type('foo.htm')).to eq 'text/html'
      expect(HTTP::Message.mime_type('foo.doc')).to eq 'application/msword'
      expect(HTTP::Message.mime_type('foo.png')).to eq 'image/png'
      expect(HTTP::Message.mime_type('foo.gif')).to eq 'image/gif'
      expect(HTTP::Message.mime_type('foo.jpg')).to eq 'image/jpeg'
      expect(HTTP::Message.mime_type('foo.jpeg')).to eq 'image/jpeg'
      expect(HTTP::Message.mime_type('foo.unknown')).to eq 'application/octet-stream'
    end

    it 'mime handler' do
      handler = lambda { |path| 'hello/world' }
      HTTP::Message.mime_type_handler = handler
      expect(HTTP::Message.mime_type_handler).not_to be_nil

      expect(HTTP::Message.get_mime_type_func).not_to be_nil

      expect(HTTP::Message.mime_type('foo.txt')).to eq 'hello/world'

      HTTP::Message.mime_type_handler = nil
      expect(HTTP::Message.mime_type('foo.txt')).to eq 'text/plain'
      HTTP::Message.set_mime_type_func(nil)
      expect(HTTP::Message.mime_type('foo.txt')).to eq 'text/plain'

      handler = lambda { |path| nil }
      HTTP::Message.mime_type_handler = handler
      expect(HTTP::Message.mime_type('foo.txt')).to eq 'application/octet-stream'
    end
  end


  it 'connect request' do
    req = HTTP::Message.new_connect_request(urify('https://foo/bar'))
    expect(req.dump).to eq "CONNECT foo:443 HTTP/1.0\r\n\r\n" 
    req = HTTP::Message.new_connect_request(urify('https://example.com/'))
    expect(req.dump).to eq "CONNECT example.com:443 HTTP/1.0\r\n\r\n" 
  end

  it 'response' do
    res = HTTP::Message.new_response('response')
    res.contenttype = 'text/plain'
    res.header.body_date = Time.at(946652400)
    expect([
      "",
      "Content-Length: 8",
      "Content-Type: text/plain",
      "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
      "Status: 200 OK",
      "response"
    ]).to eq res.dump.split(/\r\n/).sort

    expect(res.header['Content-Length']).to eq ['8']
    expect(res.headers['Content-Length']).to eq '8'
    res.header.set('foo', 'bar')
    expect([
      "",
      "Content-Length: 8",
      "Content-Type: text/plain",
      "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
      "Status: 200 OK",
      "foo: bar",
      "response"
    ]).to eq res.dump.split(/\r\n/).sort

    res = HTTP::Message.new_response(nil)
    expect([
      "Content-Length: 0",
      "Content-Type: text/html; charset=us-ascii",
      "Status: 200 OK"
    ]).to eq res.dump.split(/\r\n/).sort
  end

  it 'response cookies' do
    res = HTTP::Message.new_response('response')
    res.contenttype = 'text/plain'
    res.header.body_date = Time.at(946652400)
    expect(res.cookies).to be_nil
    res.header['Set-Cookie'] = [
      'CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT',
      'PART_NUMBER=ROCKET_LAUNCHER_0001; path=/'
    ]
    expect([
      "",
      "Content-Length: 8",
      "Content-Type: text/plain",
      "Last-Modified: Fri, 31 Dec 1999 15:00:00 GMT",
      "Set-Cookie: CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT",
      "Set-Cookie: PART_NUMBER=ROCKET_LAUNCHER_0001; path=/",
      "Status: 200 OK",
      "response"
    ]).to eq res.dump.split(/\r\n/).sort
    
    expect(res.cookies.size).to eq 2 
    expect(res.cookies[0].name).to eq 'CUSTOMER' 
    expect(res.cookies[1].name).to eq 'PART_NUMBER' 
  end

  it '#ok?' do
    res = HTTP::Message.new_response('response')
    expect(res.ok?).to eq true 
    res.status = 404
    expect(res.ok?).to eq false 
    res.status = 500
    expect(res.ok?).to eq false 
    res.status = 302
    expect(res.ok?).to eq false 
  end
end
