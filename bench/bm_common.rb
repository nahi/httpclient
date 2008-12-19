require 'benchmark'
require 'uri'
require 'fileutils'

def try_require(target)
  begin
    require target
  rescue LoadError
  end
end

try_require 'httpclient'
try_require 'net/http'
try_require 'open-uri'
try_require 'rfuzz/session'
try_require 'eventmachine'
try_require 'curb'
try_require 'httparty'
