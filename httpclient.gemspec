require './lib/httpclient/version'

Gem::Specification.new { |s|
  s.name = 'httpclient'
  s.version = HTTPClient::VERSION
  s.author = 'Hiroshi Nakamura'
  s.email = 'nahi@ruby-lang.org'
  s.executables = ['httpclient']
  s.homepage = 'https://github.com/nahi/httpclient'
  s.summary = 'gives something like the functionality of libwww-perl (LWP) in Ruby'
  s.require_paths = ['lib']
  s.files = Dir.glob('{bin,lib,sample,test}/**/*') + ['README.md']
  s.license = 'ruby'
  s.metadata = { 'yard.run' => 'yard' }
}
