source "http://rubygems.org"

# Bundle optional libraries for devel and test
group :development do
  gem 'http-cookie', '~> 1.0'
end

group :development do
  gem 'rake', :require => false
  gem 'rdoc' unless ENV['CI'] # Avoid dependency on psych for Ruby 2.5 compatibility
  gem 'test-unit'
  gem 'pry'
  gem 'rack', '~> 2.2'
  gem 'rubysspi'
  if RUBY_VERSION >= '3.2'
    gem 'rubyntlm', github: 'https://github.com/WinRb/rubyntlm/pull/64'
  else
    gem 'rubyntlm'
  end
  gem 'base64'
  gem 'rack-ntlm-test-service'
  gem 'logger'
  gem 'ostruct' # For rack-2.2.11/lib/rack/show_exceptions.rb
end

gemspec
