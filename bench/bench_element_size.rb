require 'benchmark'
require 'radix_tree' # gem install radix_tree
require 'avl_tree'

random = Random.new(0)

times = 100000
key_size = 10

def aset(h, keys)
  keys.each do |k|
    h[k] = 1
  end
end

def aref(h, keys)
  keys.each do |k|
    h[k]
  end
end

def delete(h, keys)
  keys.each do |k|
    h.delete(k)
  end
end

def run(bm, h, keys)
  name = h.class.name
  bm.report("#{name} aset (#{keys.size})") do
    aset(h, keys)
  end
  bm.report("#{name} aref (#{keys.size})") do
    aref(h, keys)
  end
  bm.report("#{name} delete (#{keys.size})") do
    delete(h, keys)
  end
end

[10000, 20000, 50000, 100000, 200000, 500000].each do |elements|
  keys = []
  elements.times do
    keys << random.bytes(key_size)
  end

  Benchmark.bm(30) do |bm|
    run(bm, Hash.new, keys)
    run(bm, RadixTree.new, keys)
    run(bm, AVLTree.new, keys)
  end
end
