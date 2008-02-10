#!/usr/bin/env ruby
#
# Installer for httpclient

require "rbconfig"
require "fileutils"

include Config

SITELIBDIR = CONFIG["sitelibdir"]
SRCPATH = File.join(File.dirname($0), 'lib')

def install_file(from, to)
  unless File.directory?(to)
    to = File.dirname(to)
  end
  to_path = File.join(to, File.basename(from))
  unless FileTest.exist?(to_path) and FileUtils.compare_file(from, to_path)
    FileUtils.install(from, to_path, :mode => 0644, :preserve => true, :verbose => true)
  end
end

def install(*path)
  from_path = File.join(SRCPATH, *path)
  if FileTest.directory?(from_path)
    to_path_sitelib = File.join(SITELIBDIR, *path)
    Dir[File.join(from_path, '*.rb')].each do |name|
      FileUtils.mkdir_p(to_path_sitelib)
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
