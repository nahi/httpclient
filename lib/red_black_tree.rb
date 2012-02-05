class RedBlackTree
  include Enumerable

  class Node
    UNDEFINED = Object.new

    attr_reader :key, :value, :color
    attr_reader :left, :right

    def initialize(key, value)
      @key, @value = key, value
      @left = @right = EMPTY
      # new node is added as RED
      @color = :RED
    end

    def set_root
      @color = :BLACK
    end

    def red?
      @color == :RED
    end

    def black?
      !red?
    end

    def empty?
      false
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
    def insert(key, value)
      ret = self
      case key <=> @key
      when -1
        check_red_pullup
        @left = @left.insert(key, value)
        if black?
          ret = check_rotate_right
        end
      when 0
        @value = value
      when 1
        check_red_pullup
        @right = @right.insert(key, value)
        if black?
          ret = check_rotate_left
        end
      end
      ret
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

    # returns [deleted_node, new_root, is_rebalance_needed]
    def delete(key)
      ret = self
      case key <=> @key
      when -1
        deleted, @left, rebalance = @left.delete(key)
        if rebalance
          ret, rebalance = rebalance_for_left_delete
        end
      when 0
        deleted = self
        ret, rebalance = delete_self
      when 1
        deleted, @right, rebalance = @right.delete(key)
        if rebalance
          ret, rebalance = rebalance_for_right_delete
        end
      end
      [deleted, ret, rebalance]
    end

    def dump_tree(io, indent = '')
      @right.dump_tree(io, indent + '  ')
      io << indent << sprintf("#<%s:0x%010x %s %s> => %s", self.class.name, __id__, @color, @key.inspect, @value.inspect) << $/
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

    # for debugging
    def check_height
      lh = @left.empty? ? 0 : @left.check_height
      rh = @right.empty? ? 0 : @right.check_height
      if red?
        if @left.red? or @right.red?
          puts dump_tree(STDERR)
          raise 'red/red assertion failed'
        end
      else
        if lh != rh
          puts dump_tree(STDERR)
          raise "black height unbalanced: #{lh} #{rh}"
        end
      end
      (lh > rh ? lh : rh) + (black? ? 1 : 0)
    end

  protected

    def children_both_black?
      @right.black? and @left.black?
    end

    def color=(color)
      @color = color
    end

    def left=(left)
      @left = left
    end

    def right=(right)
      @right = right
    end

    def color_flip(other)
      @color, other.color = other.color, @color
    end

    def node_flip(other)
      @left, other.left = other.left, @left
      @right, other.right = other.right, @right
      color_flip(other)
    end

    def delete_min
      if @left.empty?
        [self, *delete_self]
      else
        ret = self
        deleted, @left, rebalance = @left.delete_min
        if rebalance
          ret, rebalance = rebalance_for_left_delete
        end
        [deleted, ret, rebalance]
      end
    end

    # trying to rebalance when the left sub-tree is 1 level lower than the right
    def rebalance_for_left_delete
      ret = self
      rebalance = false
      if black?
        if @right.black?
          if @right.children_both_black?
            # make whole sub-tree 1 level lower and ask rebalance
            @right.color = :RED
            rebalance = true
          else
            # move 1 black from the right to the left by single/double rotation
            ret = balanced_rotate_left
          end
        else
          # flip this sub-tree into another type of 3-children node
          ret = rotate_left
          # try to rebalance in sub-tree
          ret.left, rebalance = ret.left.rebalance_for_left_delete
          raise 'should not happen' if rebalance
        end
      else # red
        if @right.children_both_black?
          # make right sub-tree 1 level lower
          color_flip(@right)
        else
          # move 1 black from the right to the left by single/double rotation
          ret = balanced_rotate_left
        end
      end
      [ret, rebalance]
    end

    # trying to rebalance when the right sub-tree is 1 level lower than the left
    # See rebalance_for_left_delete.
    def rebalance_for_right_delete
      ret = self
      rebalance = false
      if black?
        if @left.black?
          if @left.children_both_black?
            @left.color = :RED
            rebalance = true
          else
            ret = balanced_rotate_right
          end
        else
          ret = rotate_right
          ret.right, rebalance = ret.right.rebalance_for_right_delete
          raise 'should not happen' if rebalance
        end
      else # red
        if @left.children_both_black?
          color_flip(@left)
        else
          ret = balanced_rotate_right
        end
      end
      [ret, rebalance]
    end

    # move 1 black from the right to the left by single/double rotation
    def balanced_rotate_left
      if @right.left.red? and @right.right.black?
        @right = @right.rotate_right
      end
      ret = rotate_left
      ret.right.color = ret.left.color = :BLACK
      ret
    end

    # move 1 black from the left to the right by single/double rotation
    def balanced_rotate_right
      if @left.right.red? and @left.left.black?
        @left = @left.rotate_left
      end
      ret = rotate_right
      ret.right.color = ret.left.color = :BLACK
      ret
    end

    # Right single rotation
    # (b a (D c E)) where D and E are RED --> (d (B a c) E)
    #
    #   b              d
    #  / \            / \
    # a   D    ->    B   E
    #    / \        / \
    #   c   E      a   c
    #
    def rotate_left
      root = @right
      @right = root.left
      root.left = self
      root.color_flip(root.left)
      root
    end

    # Left single rotation
    # (d (B A c) e) where A and B are RED --> (b A (D c e))
    #
    #     d          b
    #    / \        / \
    #   B   e  ->  A   D
    #  / \            / \
    # A   c          c   e
    #
    def rotate_right
      root = @left
      @left = root.right
      root.right = self
      root.color_flip(root.right)
      root
    end

  private

    def check_red_pullup
      if black? and @left.red? and @right.red?
        @color = :RED
        @left.color = @right.color = :BLACK
      end
    end

    def check_rotate_right
      if @left.red?
        if @left.left.red?
          return rotate_right
        elsif @left.right.red?
          @left = @left.rotate_left
          return rotate_right
        end
      end
      self
    end

    def check_rotate_left
      if @right.red?
        if @right.right.red?
          return rotate_left
        elsif @right.left.red?
          @right = @right.rotate_right
          return rotate_left
        end
      end
      self
    end

    def delete_self
      rebalance = false
      if @left.empty? and @right.empty?
        # just remove this node and ask rebalance to the parent
        new_root = EMPTY
        if black?
          rebalance = true
        end
      elsif @left.empty? or @right.empty?
        # pick the single children
        new_root = @left.empty? ? @right : @left
        if black?
          # keep the color black
          raise 'should not happen' unless new_root.red?
          color_flip(new_root)
        else
          # just remove the red node
        end
      else
        # pick the minimum node from the right sub-tree and replace self with it
        new_root, @right, rebalance = @right.delete_min
        new_root.node_flip(self)
        if rebalance
          new_root, rebalance = new_root.rebalance_for_right_delete
        end
      end
      [new_root, rebalance]
    end

    def collect
      pool = []
      each do |key, value|
        pool << yield(key, value)
      end
      pool
    end

    class EmptyNode
      def red?
        false
      end

      def black?
        true
      end

      def empty?
        true
      end

      def value
        nil
      end

      def size
        0
      end

      def each(&block)
        # intentionally blank
      end

      # returns new_root
      def insert(key, value)
        Node.new(key, value)
      end

      # returns value
      def retrieve(key)
        UNDEFINED
      end

      # returns [deleted_node, new_root, is_rebalance_needed]
      def delete(key)
        [self, self, false]
      end

      def dump_tree(io, indent = '')
        # intentionally blank
      end

      def dump_sexp
        # intentionally blank
      end
    end
    EMPTY = Node::EmptyNode.new
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
    @root = @root.insert(key.to_s, value)
    @root.set_root
    @root.check_height if $DEBUG
  end
  alias insert []=

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
    deleted, @root, rebalance = @root.delete(key.to_s)
    unless empty?
      @root.set_root
      @root.check_height if $DEBUG
    end
    deleted.value
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
