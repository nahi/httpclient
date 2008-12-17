require 'httpclient'
require 'rfuzz/session'
require 'net/http'
require 'benchmark'
require 'uri'
require 'open-uri'
require 'eventmachine'
require 'curb'
require 'httparty'

url = ARGV.shift or raise
proxy = ENV['http_proxy'] || ENV['HTTP_PROXY']
url = URI.parse(url)
proxy = URI.parse(proxy) if proxy
threads = 2
number = 500

def do_threads(number)
  threads = []
  results = []
  number.times do
    threads << Thread.new {
      results << yield
    }
  end
  threads.map { |th| th.join }
  results
end

Benchmark.bmbm do |bm|
=begin
  # eventmachine client blocks when number > 25 or so... 
  bm.report('EM::Protocols::HttpClient2') do
    EM.run do
      query = {}
      done = false
      do_threads(threads) {
        if proxy
          host, port = proxy.host, proxy.port
        else
          host, port = url.host, url.port
        end
        path = proxy ? url.to_s : url.path
        requests = 0
        (1..number).collect {
          client = EM::Protocols::HttpClient2.connect(host, port)
          req = client.get(proxy ? url.to_s : url.path)
          query[req] = req
          req.callback {
            req.content.size
            query.delete(req)
            EM.stop if done && query.empty?
          }
        }
      }
      done = true
    end
  end
=end

  bm.report('curb') do
    do_threads(threads) {
      (1..number).collect {
        Curl::Easy.http_get(url.to_s).body_str.size
      }
    }
  end

  bm.report('RFuzz::HttpClient') do
    do_threads(threads) {
      if proxy
        host, port = proxy.host, proxy.port
      else
        host, port = url.host, url.port
      end
      path = proxy ? url.to_s : url.path
      c = RFuzz::HttpClient.new(host, port)
      result = (1..number).collect {
	c.get(path).http_body.size
      }
      c.reset
      result
    }
  end

  bm.report('Net::HTTP') do
    do_threads(threads) {
      if proxy
        c = Net::HTTP::Proxy(proxy.host, proxy.port).new(url.host, url.port)
      else
        c = Net::HTTP.new(url.host, url.port)
      end
      c.start
      result = (1..number).collect {
	c.get(url.path).read_body.size
      }
      c.finish
      result
    }
  end

  bm.report('HTTPClient') do
    c = HTTPClient.new(proxy)
    do_threads(threads) {
      (1..number).collect {
	c.get_content(url).size
      }
    }
    c.reset_all
  end

  bm.report('open-uri') do
    do_threads(threads) {
      (1..number).collect {
        open(url, :proxy => proxy) { |f|
          f.read.size
        }
      }
    }
  end

  class HTTPartyClient # need to create subclass for http_proxy
    include HTTParty
  end
  bm.report('HTTParty') do
    HTTPartyClient.http_proxy(proxy.host, proxy.port) if proxy
    do_threads(threads) {
      (1..number).collect {
        # HTTParty should accept URI object like others.
        HTTPartyClient.get(url.to_s).size
      }
    }
  end
end
