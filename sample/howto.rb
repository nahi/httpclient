#!/usr/bin/env ruby

$:.unshift(File.join('..', 'lib'))
require 'http-access2'

proxy = ENV['HTTP_PROXY']
clnt = HTTPAccess2::Client.new(proxy)
target = ARGV.shift || "http://localhost/foo.cgi"

puts
puts '= GET content directly'
puts clnt.getContent(target)

puts '= GET result object'
result = clnt.get(target)
puts '== Header object'
p result.header
puts "== Content-type"
p result.contentType
puts '== Body object'
p result.body
puts '== Content'
print result.content
puts '== GET with Block'
clnt.get(target) do |str|
  puts str
end

puts
puts '= GET with query'
puts clnt.get(target, { "foo" => "bar", "baz" => "quz" }).content

puts
puts '= GET with query 2'
puts clnt.get(target, [["foo", "bar1"], ["foo", "bar2"]]).content

# Client must be reset here to set debugDev.
# Setting debugDev to keep-alive session is ignored.
clnt.reset(target)
clnt.debugDev = STDERR
puts
puts '= GET with extraHeader'
puts clnt.get(target, nil, { "SOAPAction" => "HelloWorld" }).content

puts
puts '= GET with extraHeader 2'
puts clnt.get(target, nil, [["Accept", "text/plain"], ["Accept", "text/html"]]).content

clnt.debugDev = nil
clnt.reset(target)
