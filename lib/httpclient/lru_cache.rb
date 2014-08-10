# for DNS cache
# We do it manually because Ruby won't do it for us
# Taken from: https://github.com/kindkid/lrucache/blob/master/lib/lrucache.rb
# (MIT Licensed). Thanks!

require "lru_redux"
require 'thread'

class HTTPClient
  class LRUCache

    attr_reader :max_size, :ttl, :soft_ttl, :retry_delay

    def initialize(opts={})
      @mutex = Mutex.new

      @max_size = Integer(opts[:max_size] || 100)
      @ttl = Float(opts[:ttl] || 0)
      @soft_ttl = Float(opts[:soft_ttl] || 0)
      @retry_delay = Float(opts[:retry_delay] || 0)

      raise "max_size must not be negative" if @max_size < 0
      raise "ttl must not be negative" if @ttl < 0
      raise "soft_ttl must not be negative" if @soft_ttl < 0
      raise "retry_delay must not be negative" if @retry_delay < 0

      # we don't use thread safe variant, as we're doing thread safety ourselves
      @data = LruRedux::Cache.new(@max_size)
    end

    def fetch(key)
      # for now, this means that DNS resolving is single-threaded
      @mutex.synchronize do
        datum = @data[key]
        if datum.nil?
          store(key, value = yield)
        elsif datum.expired?
          @data.delete(key)
          store(key, value = yield)
        elsif datum.soft_expired?
          begin
            store(key, value = yield)
          rescue RuntimeError => e
            datum.soft_expiration = (Time.now + retry_delay) if retry_delay > 0
            datum.value
          end
        else
          datum.value
        end
      end
    end

    private

    def store(key, value)
      expiration = Time.now + @ttl
      soft_expiration = Time.now + @soft_ttl
      @data[key] = Datum.new(value, expiration, soft_expiration)
      value
    end

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
  end
end
