require 'rake'
require 'rake/testtask'
require 'rubygems/package_task'

task :default => :test

require 'bundler'
Bundler::GemHelper.install_tasks

Rake::TestTask.new('test') do |test|
  test.libs << 'lib'
  test.verbose = true
  test.test_files = Dir.glob('test/test_*.rb')
end
