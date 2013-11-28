# for DNS cache
# We do it manually because Ruby won't do it for us
# Taken from: https://github.com/kindkid/lrucache/blob/master/lib/lrucache.rb
# (MIT Licensed). Thanks!

require "priority_queue"

# Not thread-safe!
class HTTPClient
  class LRUCache

    attr_reader :default, :max_size, :ttl, :soft_ttl, :retry_delay

    def initialize(opts={})
      @max_size = Integer(opts[:max_size] || 100)
      @default = opts[:default]
      @eviction_handler = opts[:eviction_handler]
      @ttl = Float(opts[:ttl] || 0)
      @soft_ttl = Float(opts[:soft_ttl] || 0)
      @retry_delay = Float(opts[:retry_delay] || 0)
      raise "max_size must not be negative" if @max_size < 0
      raise "ttl must not be negative" if @ttl < 0
      raise "soft_ttl must not be negative" if @soft_ttl < 0
      raise "retry_delay must not be negative" if @retry_delay < 0

      @pqueue = PriorityQueue.new
      @data = {}
      @counter = 0
    end

    def clear
      @data.clear
      @pqueue.delete_min until @pqueue.empty?
      @counter = 0 #might as well
    end

    def include?(key)
      datum = @data[key]
      return false if datum.nil?
      if datum.expired?
        delete(key)
        false
      else
        access(key)
        true
      end
    end

    def store(key, value, args={})
      evict_lru! unless @data.include?(key) || @data.size < max_size
      ttl, soft_ttl, retry_delay = extract_arguments(args)
      expiration = expiration_date(ttl)
      soft_expiration = expiration_date(soft_ttl)
      @data[key] = Datum.new(value, expiration, soft_expiration)
      access(key)
      value
    end

    alias :[]= :store

    def fetch(key, args={})
      datum = @data[key]
      if datum.nil?
        if block_given?
          store(key, value = yield, args)
        else
          @default
        end
      elsif datum.expired?
        delete(key)
        if block_given?
          store(key, value = yield, args)
        else
          @default
        end
      elsif datum.soft_expired?
        if block_given?
          begin
            store(key, value = yield, args)
          rescue RuntimeError => e
            access(key)
            ttl, soft_ttl, retry_delay = extract_arguments(args)
            datum.soft_expiration = (Time.now + retry_delay) if retry_delay > 0
            datum.value
          end
        else
          access(key)
          datum.value
        end
      else
        access(key)
        datum.value
      end
    end

    alias :[] :fetch

    def empty?
      size == 0
    end

    def size
      @data.size
    end

    def keys
      @data.keys
    end

    def delete(key)
      @pqueue.delete(key)
      datum = @data.delete(key)
      datum.value unless datum.nil?
    end

    private

    class Datum
      attr_reader :value, :expiration, :soft_expiration
      attr_writer :soft_expiration
      def initialize(value, expiration, soft_expiration)
        @value = value
        @expiration = expiration
        @soft_expiration = soft_expiration
      end

      def expired?
        !@expiration.nil? && @expiration <= Time.now
      end

      def soft_expired?
        !@soft_expiration.nil? && @soft_expiration <= Time.now
      end
    end

    def expiration_date(ttl)
      if ttl.is_a?(Time)
        ttl
      else
        ttl = Float(ttl)
        (ttl > 0) ? (Time.now + ttl) : nil
      end
    end

    def extract_arguments(args)
      if args.is_a?(Hash)
        ttl = args[:ttl] || @ttl
        soft_ttl = args[:soft_ttl] || @soft_ttl
        retry_delay = args[:retry_delay] || @retry_delay
        [ttl, soft_ttl, retry_delay]
      else
        # legacy arg
        ttl = args || @ttl
        [ttl, @soft_ttl, @retry_delay]
      end
    end

    def evict_lru!
      key, priority = @pqueue.delete_min
      unless priority.nil?
        datum = @data.delete(key)
        @eviction_handler.call(datum.value) if @eviction_handler && datum
      end
    end

    def access(key)
      @pqueue.change_priority(key, @counter += 1)
    end

  end
end
