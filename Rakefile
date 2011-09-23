require 'rake'
require 'rake/testtask'
require 'rdoc/task'
require 'rubygems/package_task'

task :default => :test

require 'bundler'
Bundler::GemHelper.install_tasks

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new("coverage") do |rcov|
    rcov.libs << 'lib'
    rcov.pattern = 'test/test_*.rb'
  end
rescue LoadError
end

Rake::TestTask.new("test") do |test|
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
