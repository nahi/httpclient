# coding: utf-8

require 'coveralls'
Coveralls.wear!

$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), "..", "lib"))

require "rubygems"
require "rspec"
require 'digest/md5'
require 'uri'
require 'logger'
require 'stringio'
require 'webrick'
require 'webrick/httpproxy.rb'
require 'webrick/httputils'
require 'tempfile'
require 'zlib'
require 'httpclient'

require File.join(File.dirname(__FILE__), "support", "base_server.rb")
require File.join(File.dirname(__FILE__), "support", "test_servlet.rb")

SUPPORT = File.join(File.dirname(__FILE__), "support")
Dir["#{SUPPORT}/*.rb"].each { |f| require f }

GZIP_CONTENT = "\x1f\x8b\x08\x00\x1a\x96\xe0\x4c\x00\x03\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00"
DEFLATE_CONTENT = "\x78\x9c\xcb\x48\xcd\xc9\xc9\x07\x00\x06\x2c\x02\x15"
GZIP_CONTENT.force_encoding('BINARY') if GZIP_CONTENT.respond_to?(:force_encoding)
DEFLATE_CONTENT.force_encoding('BINARY') if DEFLATE_CONTENT.respond_to?(:force_encoding)

LARGE_STR = '1234567890' * 100_000

RSpec.configure do |config|
  config.before(:all) do
    @srv = MainServer.new
    @proxy = ProxyServer.new
  end
end
