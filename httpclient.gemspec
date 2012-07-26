require 'rubygems'
SPEC = Gem::Specification.new do |s|
  s.name = "httpclient"
  s.version = "2.2.0"
  s.date = "2011-04-08"
  s.author = "NAKAMURA, Hiroshi"
  s.email = "nahi@ruby-lang.org"
  s.homepage = "http://github.com/nahi/httpclient"
  s.platform = Gem::Platform::RUBY
  s.summary = "gives something like the functionality of libwww-perl (LWP) in Ruby"
  s.files = Dir.glob("{lib}/**/*")
  s.require_path = "lib"
  s.has_rdoc = true
end
