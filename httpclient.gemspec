require 'rubygems'
Gem::Specification.new { |s|
  s.name = 'glebtv-httpclient'
  s.version = '3.0.0'
  s.date = '2013-05-13'
  s.author = 'glebtv'
  s.email = 'glebtv@gmail.com'
  s.executables = ['httpclient']
  s.homepage = 'http://github.com/glebtv/httpclient'
  s.platform = Gem::Platform::RUBY
  s.summary = 'Fork of httpclient with some fixes and patches I needed. Please use original gem instead'
  s.files = Dir.glob('{bin,lib,sample,test}/**/*') + ['README.md']
  s.require_path = 'lib'
  s.license = 'ruby'
}
