# encoding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'httpclient/version'

Gem::Specification.new do |s|
  s.name = 'glebtv-httpclient'
  s.version = HTTPClient::VERSION
  s.authors = ['glebtv', 'Hiroshi Nakamura']
  s.email = 'glebtv@gmail.com'
  s.executables = ['httpclient']
  s.homepage = 'http://github.com/glebtv/httpclient'
  s.platform = Gem::Platform::RUBY
  s.summary = 'Fork of httpclient with some fixes and patches I needed. Please use original gem instead'
  s.files = Dir.glob('{bin,lib,sample,test}/**/*') + ['README.md']
  s.require_path = 'lib'
  s.license = 'ruby'
end
