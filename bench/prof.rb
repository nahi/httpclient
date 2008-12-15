require 'httpclient'
require 'ruby-prof'

num = 100
url = ARGV.shift
url = URI.parse(url)
c = HTTPClient.new
c.debug_dev = STDOUT if $DEBUG
GC.disable
RubyProf.start
num.times do
  c.get(url).content.size
end
result = RubyProf.stop
printer = RubyProf::GraphHtmlPrinter.new(result)
printer.print(STDOUT)
