# coding: utf-8
require 'spec_helper'

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

describe 'KeepAlive' do
  it 'disconnected' do
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
        Thread.abort_on_exception = true
        client.get(endpoint).content.should eq "12345"
      }
    }.each { |th| th.join }
    # send 5 requests, which should get KeepAliveDesconnected.
    # doing these requests, rest keep-alive connections are invalidated.
    (0...5).to_a.map {
      Thread.new {
        Thread.abort_on_exception = true
        client.get(endpoint).content.should eq "23456"
      }
    }.each { |th| th.join }
    # rest requests won't get KeepAliveDisconnected; how can I check this?
    (0...10).to_a.map {
      Thread.new {
        Thread.abort_on_exception = true
        client.get(endpoint).content.should eq "34567"
      }
    }.each { |th| th.join }
  end

  it 'works' do
    client = HTTPClient.new
    server = TCPServer.open('127.0.0.1', 0)
    server_thread = Thread.new {
      Thread.abort_on_exception = true
      sock = server.accept
      create_keepalive_thread(10, sock)
    }
    url = "http://127.0.0.1:#{server.addr[1]}/"
    # content-length
    5.times do
      client.get(url).body.should eq '12345'
    end
    # chunked
    5.times do
      client.get(url + 'chunked').body.should eq 'abcdefghijklmnopqrstuvwxyz1234567890abcdef'
    end
    server_thread.join
  end
end
