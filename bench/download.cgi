#!/usr/local/bin/ruby

print "Content-Type: application/octet-stream\r\n"
print "Transfer-Encoding: chunked\r\n"
print "\r\n"

def dump_chunk_size(size)
  sprintf("%x", size) + "\r\n"
end

def dump_chunk(str)
  dump_chunk_size(str.size) + str + "\r\n"
end

buf_size = 1024 * 16
STDOUT.sync = true
File.open(File.expand_path('10M.bin', File.dirname(__FILE__))) do |file|
  buf = ''
  while !file.read(buf_size, buf).nil?
    print dump_chunk(buf)
  end
  print dump_chunk_size(0) + "\r\n"
end
