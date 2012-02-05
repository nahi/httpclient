require 'rubygems'
Gem::Specification.new { |s|
  s.name = "avl_tree"
  s.version = "1.1.0"
  s.date = "2012-02-05"
  s.author = "Hiroshi Nakamura"
  s.email = "nahi@ruby-lang.org"
  s.homepage = "http://github.com/nahi/avl_tree"
  s.platform = Gem::Platform::RUBY
  s.summary = "AVL tree and Red-black tree in Ruby"
  s.files = Dir.glob('{lib,bench,test}/**/*') + ['README']
  s.require_path = "lib"
}
