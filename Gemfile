source "http://rubygems.org"

platform :rbx do
  gem 'rubysl', '~> 2.0'
  gem 'rubinius-developer_tools'
end

# Bundle optional libraries for devel and test
group :development do
  gem 'http-cookie', '~> 1.0'
end

group :development do
  gem 'rake', :require => false
  gem 'rdoc'
  gem 'simplecov', :platforms => [:ruby_19, :ruby_20, :ruby_21]
  # For Jenkins
  gem 'test-unit'
  # ci_reporter 2.x doesn't support Ruby 1.8
  gem 'ci_reporter', '~> 1.9'
  gem 'simplecov-rcov', :platforms => [:ruby_19, :ruby_20, :ruby_21]
  gem 'pry'
  gem 'rack', '~> 1.0'
  gem 'rubysspi'
  gem 'rubyntlm'
  gem 'rack-ntlm-test-service'
end

gemspec
