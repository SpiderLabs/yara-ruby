require 'rubygems'
require 'bundler'
require 'rake/extensiontask'

begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
  gem.name = "yara"
  gem.homepage = "http://github.com/SpiderLabs/yara-ruby"
  gem.summary = %Q{Ruby bindings for libyara}
  gem.description = %Q{Ruby bindings for the yara malware analysis library}
  gem.email = "emonti@trustwave.com"
  gem.authors = ["Eric Monti"]

  gem.extensions = FileList['ext/**/extconf.rb']

  # Include your dependencies below. Runtime dependencies are required when using your gem,
  # and development dependencies are only needed for development (ie running rake tasks, tests, etc)
  #  gem.add_runtime_dependency 'jabber4r', '> 0.1'
  #  gem.add_development_dependency 'rspec', '> 1.2.3'
end
Jeweler::RubygemsDotOrgTasks.new

Rake::ExtensionTask.new("yara_native")

CLEAN.include("lib/*.bundle")
CLEAN.include("lib/*.so")

require 'rspec/core'
require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec => :compile ) do |spec|
  spec.pattern = FileList['spec/**/*_spec.rb']
end

RSpec::Core::RakeTask.new(:rcov) do |spec|
  spec.pattern = 'spec/**/*_spec.rb'
  spec.rcov = true
end

task :default => :spec

require 'yard'
YARD::Rake::YardocTask.new
