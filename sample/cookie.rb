#!/usr/bin/env ruby

$:.unshift(File.join('..', 'lib'))
require 'http-access2'

proxy = ENV['HTTP_PROXY']
clnt = HTTPAccess2::Client.new(proxy)
clnt.set_cookie_store("cookie.dat")
clnt.debug_dev = STDOUT if $DEBUG

while urlstr = ARGV.shift
  response = clnt.get(urlstr){ |data|
    print data
  }
  p response.contenttype
end

clnt.save_cookie_store
