require 'benchmark'
require 'uri'
require 'fileutils'

def try_require(target)
  begin
    require target
  rescue LoadError
    warn("#{target} not loaded")
  end
end

try_require 'httpclient'
require 'net/http'

# following Net code block is not copirighed by me.
# see: http://7fff.com/2008/12/20/faster-nethttp-for-ruby-186
module Net
  class BufferedIO
    alias rbuf_fill_replaced_by_bm rbuf_fill
    BUFSIZE = 1024 * 16  
    def rbuf_fill  
      # HTTPS can't use the non-blocking strategy below in 1.8.6; so at least  
      # increase buffer size over 1.8.6 default of 1024  
      if !@io.respond_to? :read_nonblock  
        timeout(@read_timeout) {  
          @rbuf << @io.sysread(BUFSIZE)  
        }  
        return  
      end  
      # non-blocking  
      begin  
        @rbuf << @io.read_nonblock(BUFSIZE)  
      rescue Errno::EWOULDBLOCK  
        if IO.select([@io], nil, nil, @read_timeout)  
          @rbuf << @io.read_nonblock(BUFSIZE)  
        else  
          raise Timeout::TimeoutError  
        end  
      end  
    end
  end
end

require 'open-uri'
try_require 'rfuzz/session'
try_require 'eventmachine'
try_require 'curb'
try_require 'httparty'
