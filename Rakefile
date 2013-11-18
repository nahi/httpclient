require 'rake'

require 'rdoc/task'

Rake::RDocTask.new("doc") do |rdoc|
  load 'lib/httpclient/version.rb'
  rdoc.rdoc_dir = 'doc'
  rdoc.title = "HTTPClient Library Document: Version #{HTTPClient::VERSION}"
  rdoc.rdoc_files.include('README.md')
  rdoc.rdoc_files.include('CHANGELOG.rdoc')
  rdoc.rdoc_files.include('lib/httpclient/*.rb')
  rdoc.rdoc_files.include('lib/httpclient.rb')
end

require "bundler/gem_tasks"

require 'rspec/core/rake_task'

desc "Run specs"
RSpec::Core::RakeTask.new

task :default => 'spec'
