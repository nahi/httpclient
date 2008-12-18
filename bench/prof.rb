require 'httpclient'
require 'ruby-prof'

num = 1
url = ARGV.shift
url = URI.parse(url)
c = HTTPClient.new
c.debug_dev = STDOUT if $DEBUG
GC.disable
RubyProf.start
File.open('testfile_18826') do |file|
  puts c.post(url, {'upload' => file}).content
end
result = RubyProf.stop
printer = RubyProf::GraphHtmlPrinter.new(result)
printer.print(STDOUT)
