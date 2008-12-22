require 'bm_common'

require 'multipart'

url = ARGV.shift or raise
proxy = ENV['http_proxy'] || ENV['HTTP_PROXY']
url = URI.parse(url)
proxy = URI.parse(proxy) if proxy
threads = 1
number = 10
msize = 10

testfile = File.expand_path("testfile", File.dirname(__FILE__))
require 'openssl'
File.open(testfile, 'wb') do |file|
  (msize * 1024).times do
    file.write(OpenSSL::Random.random_bytes(1024))
  end
end
upload_size = msize * 1024 * 1024

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

  if defined?(Curl)
    bm.report('curb') do
      fields = [Curl::PostField.file('upload', testfile)]
      do_threads(threads) {
        (1..number).collect {
          p Curl::Easy.http_post(url.to_s, *fields).body_str.to_i
        }
      }
    end
  end

  if defined?(RFuzz)
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
  end
=end

  if defined?(Net::HTTP)
    bm.report('Net::HTTP + multipart') do
      do_threads(threads) {
        if proxy
          c = Net::HTTP::Proxy(proxy.host, proxy.port).new(url.host, url.port)
        else
          c = Net::HTTP.new(url.host, url.port)
        end
        c.start
        result = (1..number).collect {
          req = Net::HTTP::Post.new(url.path)
          file = Net::HTTP::FileForPost.new(testfile)
          req.set_multipart_data('upload' => file)
          raise if upload_size != c.request(req).read_body.to_i
        }
        c.finish
        result
      }
    end
  end

  if defined?(HTTPClient)
    bm.report('HTTPClient') do
      c = HTTPClient.new(proxy)
      do_threads(threads) {
        (1..number).collect {
          File.open(testfile) do |file|
            raise if upload_size != c.post(url, {'upload' => file}).content.to_i
          end
        }
      }
      c.reset_all
    end
  end

=begin
  if defined?(HTTParty)
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
=end
end
