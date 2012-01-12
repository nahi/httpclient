class AVLTree
  include Enumerable

  class Node
    UNDEFINED = Object.new

    class EmptyNode
      def height
        0
      end

      def size
        0
      end

      def each(&block)
        # intentionally blank
      end

      def store(key, value)
        Node.new(key, value)
      end

      def retrieve(key)
        UNDEFINED
      end

      def delete(key)
        [nil, self]
      end

      def dump_tree(io, indent = '')
        # intentionally blank
      end

      def dump_sexp
        # intentionally blank
      end
    end
    EMPTY = Node::EmptyNode.new

    attr_reader :key, :value
    attr_reader :left, :right

    def initialize(key, value)
      @key, @value = key, value
      @left = @right = EMPTY
      @height = nil
    end

    def size
      @left.size + 1 + @right.size
    end

    # inorder
    def each(&block)
      @left.each(&block)
      yield [@key, @value]
      @right.each(&block)
    end
    
    def each_key
      each do |k, v|
        yield k
      end
    end
    
    def each_value
      each do |k, v|
        yield v
      end
    end

    def keys
      collect { |k, v| k }
    end

    def values
      collect { |k, v| v }
    end

    # returns new_root
    def store(key, value)
      @height = nil
      case key <=> @key
      when -1
        @left = @left.store(key, value)
      when 0
        @value = value
      when 1
        @right = @right.store(key, value)
      end
      rotate
    end

    # returns value
    def retrieve(key)
      case key <=> @key
      when -1
        @left.retrieve(key)
      when 0
        @value
      when 1
        @right.retrieve(key)
      end
    end

    # returns [deleted_value, new_root]
    def delete(key)
      @height = nil
      case key <=> @key
      when -1
        deleted, @left = @left.delete(key)
        [deleted, rotate]
      when 0
        delete_self
      when 1
        deleted, @right = @right.delete(key)
        [deleted, rotate]
      end
    end

    def dump_tree(io, indent = '')
      @right.dump_tree(io, indent + '  ')
      io << indent << sprintf("#<%s:0x%010x %d %s> => %s", self.class.name, __id__, height, @key.inspect, @value.inspect) << $/
      @left.dump_tree(io, indent + '  ')
    end

    def dump_sexp
      left = @left.dump_sexp
      right = @right.dump_sexp
      if left or right
        '(' + [@key, left || '-', right].compact.join(' ') + ')'
      else
        @key
      end
    end

    def height
      @height ||= [@left.height, @right.height].max + 1
    end

  protected

    def left=(left)
      @left = left
    end

    def right=(right)
      @right = right
    end

  private

    def delete_self
      if leaf?
        [@value, EMPTY]
      else
        # TODO: when we delete a node (not a leaf), pick heigher sub tree at
        # first, then add all rest nodes to the sub tree. Find smarter way.
        if @left.height >= @right.height
          root, rest = @left, @right
        else
          root, rest = @right, @left
        end
        rest.each do |k, v|
          root = root.store(k, v)
        end
        [@value, root]
      end
    end

    def leaf?
      @right == EMPTY and @left == EMPTY
    end

    def rotate
      case @left.height - @right.height
      when +2
        if @left.left.height >= @left.right.height
          rotate_LL
        else
          rotate_LR
        end
      when -2
        if @right.left.height <= @right.right.height
          rotate_RR
        else
          rotate_RL
        end
      else
        self
      end
    end

    def rotate_RR
      root = @right
      @right = root.left
      root.left = self
      root
    end

    def rotate_LL
      root = @left
      @left = root.right
      root.right = self
      root
    end

    def rotate_RL
      other = @right
      root = other.left
      @right = root.left
      other.left = root.right
      root.left = self
      root.right = other
      root
    end

    def rotate_LR
      other = @left
      root = other.right
      @left = root.right
      other.right = root.left
      root.right = self
      root.left = other
      root
    end

    def collect
      pool = []
      each do |key, value|
        pool << yield(key, value)
      end
      pool
    end
  end

  DEFAULT = Object.new

  attr_accessor :default
  attr_reader :default_proc
  
  def initialize(default = DEFAULT, &block)
    if block && default != DEFAULT
      raise ArgumentError, 'wrong number of arguments'
    end
    @root = Node::EMPTY
    @default = default
    @default_proc = block
  end

  def empty?
    @root == Node::EMPTY
  end

  def size
    @root.size
  end
  alias length size

  def each(&block)
    if block_given?
      @root.each(&block)
      self
    else
      Enumerator.new(@root)
    end
  end
  alias each_pair each

  def each_key
    if block_given?
      @root.each do |k, v|
        yield k
      end
      self
    else
      Enumerator.new(@root, :each_key)
    end
  end

  def each_value
    if block_given?
      @root.each do |k, v|
        yield v
      end
      self
    else
      Enumerator.new(@root, :each_value)
    end
  end

  def keys
    @root.keys
  end

  def values
    @root.values
  end

  def clear
    @root = Node::EMPTY
  end

  def []=(key, value)
    @root = @root.store(key.to_s, value)
  end
  alias store []=

  def key?(key)
    @root.retrieve(key.to_s) != Node::UNDEFINED
  end
  alias has_key? key?

  def [](key)
    value = @root.retrieve(key.to_s)
    if value == Node::UNDEFINED
      default_value
    else
      value
    end
  end

  def delete(key)
    deleted, @root = @root.delete(key.to_s)
    deleted
  end

  def dump_tree(io = '')
    @root.dump_tree(io)
    io << $/
    io
  end

  def dump_sexp
    @root.dump_sexp || ''
  end

  def to_hash
    inject({}) { |r, (k, v)| r[k] = v; r }
  end

private

  def default_value
    if @default != DEFAULT
      @default
    elsif @default_proc
      @default_proc.call
    else
      nil
    end
  end
end
