require 'rubygems'
SPEC = Gem::Specification.new do |s|
  s.name = "http-access"
  s.version = "2.0.8"
  s.date = "2007-06-30"
  s.author = "NAKAMURA, Hiroshi"
  s.email = "nahi@ruby-lang.org"
  s.homepage = "http://dev.ctor.org/http-access2"
  s.platform = Gem::Platform::RUBY
  s.summary = "gives something like the functionality of libwww-perl (LWP) in Ruby"
  s.files = Dir.glob("{lib}/**/*")
  s.require_path = "lib"
  s.has_rdoc = true
end
