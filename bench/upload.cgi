#!/usr/local/bin/ruby

require 'cgi'

cgi = CGI.new
print "Content-Type: text/plain\r\n\r\n"
print cgi['upload'].size.to_s + "\n"
