$:.unshift(File.join('..', 'lib'))
require 'http-access2'

urlstr = ARGV.shift

proxy = ENV['HTTP_PROXY'] || ENV['http_proxy']
h = HTTPAccess2::Client.new(proxy)

count = 20

res = []
g = []
for i in 0..count
  g << Thread.new {
    res[i] = h.get(urlstr)
  }
end

g.each do |th|
  th.join
end

for i in 0..(count - 1)
  raise unless (res[i].content == res[i + 1].content)
end

puts 'ok'
