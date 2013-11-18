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
require 'httpclient'

require File.join(File.dirname(__FILE__), "support", "base_server.rb")
SUPPORT = File.join(File.dirname(__FILE__), "support")
Dir["#{SUPPORT}/*.rb"].each { |f| require f }

RSpec.configure do |config|
  config.before(:all) do
    @srv = MainServer.new
    @proxy = ProxyServer.new
  end
end
