$:.unshift( File.join( '..', 'lib' ))
require 'http-access2'

urlstr = ARGV.shift

proxy = ENV[ 'HTTP_PROXY' ] || ENV[ 'http_proxy' ]
h = HTTPAccess2::Client.new( proxy )

res = []
g = []
for i in 0..29
  g << Thread.new {
    res[ i ] = h.get( urlstr )
  }
end

g.each do | th |
  th.join
end

for i in 0..28
  raise unless ( res[ i ].body.content == res[ i + 1 ].body.content )
end

puts 'ok'
