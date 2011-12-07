require 'rubygems'
Gem::Specification.new { |s|
  s.name = "httpclient"
  s.version = "2.2.4"
  s.date = "2011-12-08"
  s.author = "Hiroshi Nakamura"
  s.email = "nahi@ruby-lang.org"
  s.homepage = "http://github.com/nahi/httpclient"
  s.platform = Gem::Platform::RUBY
  s.summary = "gives something like the functionality of libwww-perl (LWP) in Ruby"
  s.files = Dir.glob("{lib,sample,test}/**/*")
  s.require_path = "lib"
}
