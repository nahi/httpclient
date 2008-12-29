require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'

task :default => :gem

begin
  require 'rake/gempackagetask'
  load 'httpclient.gemspec'
  Rake::GemPackageTask.new(SPEC) do |pkg|
    pkg.need_zip = true
    pkg.need_tar = true
  end
rescue LoadError
end

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
  test.warning = true
  test.pattern = 'test/test_*.rb'
end

Rake::RDocTask.new("doc") do |rdoc|
  load 'lib/httpclient.rb'
  rdoc.rdoc_dir = 'doc'
  rdoc.title = "HTTPClient Library Document: Version #{HTTPClient::VERSION}"
  rdoc.rdoc_files.include('README.txt')
  rdoc.rdoc_files.include('lib/httpclient/*.rb')
  rdoc.rdoc_files.include('lib/httpclient.rb')
end

task 'tags' do
  chdir 'lib'
  sh 'rtags --vi httpclient.rb httpclient/*.rb'
end
