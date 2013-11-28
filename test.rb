#!/usr/bin/env ruby

$:.unshift(File.join('.', 'lib'))
require 'httpclient'

clnt = HTTPClient.new()
site = ARGV.shift
threads = []
15.times do
  threads << Thread.new do
    loop do
      puts "GET #{site}"
      cnt = clnt.get_content site
      sleep 1
    end
  end
end

threads.map(&:join)
