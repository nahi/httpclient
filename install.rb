#!/usr/bin/env ruby
#
# Installer for http-access2
# Copyright (C) 2001 Michael Neumann and NAKAMURA, Hiroshi.

require "rbconfig"
require "ftools"
include Config

RV = CONFIG["MAJOR"] + "." + CONFIG["MINOR"]
DSTPATH = CONFIG["sitedir"] + "/" +  RV 

begin
  unless FileTest.directory?("lib/http-access2")
    raise RuntimeError.new("'lib/http-access2' not found.")
  end

  File.mkpath DSTPATH + "/http-access2", true 
  Dir["lib/http-access2/*.rb"].each do |name|
    File.install name, "#{DSTPATH}/http-access2/#{File.basename name}", 0644, true
  end

  Dir["lib/*.rb"].each do |name|
    File.install name, "#{DSTPATH}/#{File.basename name}", 0644, true
  end

rescue 
  puts "install failed!"
  puts $!
else
  puts "install succeed!"
end
