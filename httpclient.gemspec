require 'rubygems'
Gem::Specification.new { |s|
  s.name = 'httpclient'
  s.version = '2.4.0'
  s.date = '2014-06-08'
  s.author = 'Hiroshi Nakamura'
  s.email = 'nahi@ruby-lang.org'
  s.executables = ['httpclient']
  s.homepage = 'http://github.com/nahi/httpclient'
  s.platform = Gem::Platform::RUBY
  s.summary = 'gives something like the functionality of libwww-perl (LWP) in Ruby'
  s.files = Dir.glob('{bin,lib,sample,test}/**/*') + ['README.md']
  s.require_path = 'lib'
  s.license = 'ruby'
}
