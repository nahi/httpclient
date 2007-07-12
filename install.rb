#!/usr/bin/env ruby
#
# Installer for httpclient

require "rbconfig"
require "ftools"

include Config

RV = CONFIG["MAJOR"] + "." + CONFIG["MINOR"]
SITELIBDIR = CONFIG["sitedir"] + "/" +  RV 
SRCPATH = File.join(File.dirname($0), 'lib')

def install_file(from, to)
  to_path = File.catname(from, to)
  unless FileTest.exist?(to_path) and File.compare(from, to_path)
    File.install(from, to_path, 0644, true)
  end
end

def install(*path)
  from_path = File.join(SRCPATH, *path)
  if FileTest.directory?(from_path)
    to_path_sitelib = File.join(SITELIBDIR, *path)
    Dir[File.join(from_path, '*.rb')].each do |name|
      File.mkpath(to_path_sitelib, true)
      install_file(name, to_path_sitelib)
    end
  else
    install_file(from_path, File.join(SITELIBDIR, *path))
  end
end

begin
  install('httpclient.rb')
  install('httpclient')
  install('httpclient', 'cacert.p7s')
  install('http-access2.rb')
  install('http-access2')

  puts "install succeed!"

rescue 
  puts "install failed!"
  raise

end
