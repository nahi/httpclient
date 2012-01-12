require 'rubygems'
Gem::Specification.new { |s|
  s.name = "avl_tree"
  s.version = "1.0.0.dev.1"
  s.date = "2012-01-12"
  s.author = "Hiroshi Nakamura"
  s.email = "nahi@ruby-lang.org"
  s.homepage = "http://github.com/nahi/avl_tree"
  s.platform = Gem::Platform::RUBY
  s.summary = "Naive implementation of AVL tree for Ruby"
  s.files = Dir.glob('{lib,test}/**/*') + ['README']
  s.require_path = "lib"
}
