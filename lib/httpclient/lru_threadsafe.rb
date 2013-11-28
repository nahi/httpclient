# Make LRU cache Threadsafe
# Idea from: https://github.com/SamSaffron/lru_redux/blob/master/lib/lru_redux/thread_safe_cache.rb
# (MIT License)

require 'thread'
require 'monitor'

class HTTPClient::ThreadSafeCache < HTTPClient::LRUCache
  include MonitorMixin

  def initialize(opts={})
    super(opts)
  end

  def self.synchronize(*methods)
    methods.each do |method|
      define_method method do |*args, &blk|
        synchronize do
          super(*args, &blk)
        end
      end
    end

    alias :[]= :store
    alias :[] :fetch
  end

  synchronize :fetch, :store, :delete, :clear, :include?, :empty, :size, :keys 
end
