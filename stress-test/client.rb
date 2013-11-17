# encoding: utf-8
lib = File.expand_path('../../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'httpclient'

require 'thread'

threads = []
# clnt = HTTPClient.new()

# 20.times do 
#   threads << Thread.new do
#     loop do
#       clnt.get("http://localhost:7000/#{rand(1000..10000).to_s}.html") do |str|
#         puts str.length if str.length != 1300000
#       end
#     end
#   end
# end
# 
# clnt = HTTPClient.new()
# 10.times do
#   threads << Thread.new do
#     loop do
#       begin
#       clnt.get("http://#{rand(10000...200000)}.test.local/test.htm") do |str|
#         puts str.length if str.length != 1300000
#       end
#       rescue
#       end
#     end
#   end
# end

20.times do 
  threads << Thread.new do
    loop do
      clnt = HTTPClient.new()
      clnt.get("http://localhost:7000/#{rand(1000..10000).to_s}.html") do |str|
        puts str.length if str.length != 1300000
      end
    end
  end
end

def ostats(last_stat = nil)
 stats = Hash.new(0)
 ObjectSpace.each_object {|o| stats[o.class] += 1}

 stats.sort {|(k1,v1),(k2,v2)| v2 <=> v1}.each do |k,v|
   next if v < 25
   printf "%-30s  %10d", k, v
   printf " | delta %10d", (v - last_stat[k]) if last_stat
   puts
 end

 stats
end

mstat = nil

threads << Thread.new do
  loop do
    mstat = ostats(mstat)
    puts '-' * 80
    sleep 1
  end
end

threads.each do |t|
  t.join
end