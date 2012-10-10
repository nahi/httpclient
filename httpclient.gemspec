require 'rubygems'
Gem::Specification.new { |s|
  s.name = 'httpclient'
  s.version = '2.3.0'
  s.date = '2012-10-10'
  s.author = 'Hiroshi Nakamura'
  s.email = 'nahi@ruby-lang.org'
  s.executables = ['httpclient']
  s.homepage = 'http://github.com/nahi/httpclient'
  s.platform = Gem::Platform::RUBY
  s.summary = 'gives something like the functionality of libwww-perl (LWP) in Ruby'
  s.files = Dir.glob('{bin,lib,sample,test}/**/*') + ['README.txt']
  s.require_path = 'lib'
}
