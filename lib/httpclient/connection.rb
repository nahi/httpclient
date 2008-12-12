# HTTPClient - HTTP client library.
# Copyright (C) 2000-2008  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.

# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


class HTTPClient


  # magage a connection(one request and response to it).
  #
  class Connection
    attr_accessor :async_thread

    def initialize(header_queue = [], body_queue = [])
      @headers = header_queue
      @body = body_queue
      @async_thread = nil
      @queue = Queue.new
    end

    def finished?
      if !@async_thread
        # Not in async mode.
        true
      elsif @async_thread.alive?
        # Working...
        false
      else
        # Async thread have been finished.
        @async_thread.join
        true
      end
    end

    def pop
      @queue.pop
    end

    def push(result)
      @queue.push(result)
    end

    def join
      unless @async_thread
        false
      else
        @async_thread.join
      end
    end
  end


end
