#!/usr/bin/env ruby

# wcat for http-access2
# Copyright (C) 2001 TAKAHASHI Masayoshi

$:.unshift( File.join( '..', 'lib' ))
require 'http-access2'

if ENV['HTTP_PROXY']
  h = HTTPAccess2::Client.new(ENV['HTTP_PROXY'])
else
  h = HTTPAccess2::Client.new()
end
  
while urlstr = ARGV.shift
  response = h.get(urlstr){ |data|
    print data
  }
  p response.header[ 'content-type' ]
  p response.body.size
end
