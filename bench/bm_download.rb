require 'bm_common'

url = ARGV.shift or raise
proxy = ENV['http_proxy'] || ENV['HTTP_PROXY']
url = URI.parse(url)
proxy = URI.parse(proxy) if proxy
threads = 1
number = 20

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
  if defined?(Curl)
    bm.report('curb') do
      do_threads(threads) {
        (1..number).collect {
          Curl::Easy.download(url.to_s, 'download_curb')
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
          File.open('download_rfuzz', 'wb') do |file|
            file.write(c.get(path).http_body)
          end
        }
        c.reset
        result
      }
    end
  end

  if defined?(Net::HTTP)
    bm.report('Net::HTTP') do
      do_threads(threads) {
        if proxy
          c = Net::HTTP::Proxy(proxy.host, proxy.port).new(url.host, url.port)
        else
          c = Net::HTTP.new(url.host, url.port)
        end
        c.start
        result = (1..number).collect {
          File.open('download_net_http', 'wb') do |file|
            c.get(url.path) do |data|
              file.write(data)
            end
          end
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
          File.open('download_httpclient', 'wb') do |file|
            c.get_content(url) do |data|
              file.write(data)
            end
          end
        }
      }
      c.reset_all
    end
  end

  if defined?(OpenURI)
    bm.report('open-uri') do
      size = 16 * 1024
      do_threads(threads) {
        (1..number).collect {
          File.open('download_open-uri', 'wb') do |file|
            open(url, :proxy => proxy) { |f|
              FileUtils.copy_stream(f, file)
            }
          end
        }
      }
    end
  end

  if defined?(HTTParty)
    class HTTPartyClient # need to create subclass for http_proxy
      include HTTParty
    end
    bm.report('HTTParty') do
      HTTPartyClient.http_proxy(proxy.host, proxy.port) if proxy
      do_threads(threads) {
        (1..number).collect {
          File.open('download_httparty', 'wb') do |file|
            file.write(HTTPartyClient.get(url.to_s))
          end
        }
      }
    end
  end
end
