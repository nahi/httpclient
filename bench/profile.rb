require File.expand_path('../lib/avl_tree', File.dirname(__FILE__))

random = Random.new(0)

TIMES = 200000
key_size = 10

h = AVLTree.new
TIMES.times do
  h[random.bytes(key_size)] = 1
  h[random.bytes(key_size)]
  h.delete(random.bytes(key_size))
end
