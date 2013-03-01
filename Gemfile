source "http://rubygems.org"

platform :jruby do
  gem 'jruby-openssl'
end

group :development do
  gem 'rake', :require => false
  gem 'rdoc'
  gem 'simplecov'
  # For Jenkins
  gem 'test-unit'
  gem 'ci_reporter'
  gem 'simplecov-rcov'
  gem 'pry'
  gem 'rack'
  gem 'rubysspi'
  gem 'rubyntlm'
  gem 'rack-ntlm-test-service', :git => "https://git@github.com/johncant/rack-ntlm-test-service"
  gem 'rack-ntlm-test-service', :path => "~/reevoo/rack-ntlm-test-service"
end

gemspec
