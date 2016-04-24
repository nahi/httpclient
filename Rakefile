require 'bundler/setup'
require 'rake/testtask'
require 'rdoc/task'
require 'bundler/gem_tasks'

task :default => :test

ENV['CI_REPORTS'] = File.expand_path('./reports', File.dirname(__FILE__))
task :test => ['test-run']

Rake::TestTask.new('test-run') do |test|
  test.libs << 'lib'
  test.verbose = true
  test.test_files = Dir.glob('test/test_*.rb')
end

Rake::RDocTask.new("doc") do |rdoc|
  load 'lib/httpclient/version.rb'
  rdoc.rdoc_dir = 'doc'
  rdoc.title = "HTTPClient Library Document: Version #{HTTPClient::VERSION}"
  rdoc.rdoc_files.include('README.txt')
  rdoc.rdoc_files.include('lib/httpclient/*.rb')
  rdoc.rdoc_files.include('lib/httpclient.rb')
end

task 'tags' do
  #sh 'rtags --vi lib/httpclient.rb lib/oauthclient.rb lib/hexdump.rb lib/httpclient/*.rb'
  sh 'ctags lib/httpclient.rb lib/oauthclient.rb lib/hexdump.rb lib/httpclient/*.rb'
end
