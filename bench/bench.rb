require 'benchmark'
require 'radix_tree' # gem install radix_tree
require 'avl_tree'

random = Random.new(0)

TIMES = 100000
key_size = 10

def aset(h, keys)
  TIMES.times do |idx|
    k = keys[idx]
    h[k] = 1
  end
end

def aref(h, keys)
  TIMES.times do |idx|
    k = keys[idx]
    h[k]
  end
end

def delete(h, keys)
  TIMES.times do |idx|
    k = keys[idx]
    h.delete(k)
  end
end

def run(bm, h, keys)
  name = h.class.name
  bm.report("#{name} aset") do
    aset(h, keys)
  end
  bm.report("#{name} aref") do
    aref(h, keys)
  end
  bm.report("#{name} delete") do
    delete(h, keys)
  end
end

keys = []
TIMES.times do
  keys << random.bytes(key_size)
end

Benchmark.bmbm do |bm|
  run(bm, Hash.new, keys)
  run(bm, RadixTree.new, keys)
  run(bm, AVLTree.new, keys)
end
