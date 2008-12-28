# HTTPClient - HTTP client library.
# Copyright (C) 2000-2008  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.
#
# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


require 'uri'


class HTTPClient


  module Util
    def keyword_argument(args, *field)
      if args.size == 1 and args[0].is_a?(Hash)
        args[0].values_at(*field)
      else
        args
      end
    end

    def urify(uri)
      if uri.nil?
        nil
      elsif uri.is_a?(URI)
        uri
      else
        URI.parse(uri.to_s)
      end
    end

    def uri_part_of(uri, part)
      ((uri.scheme == part.scheme) and
       (uri.host == part.host) and
       (uri.port == part.port) and
       uri.path.upcase.index(part.path.upcase) == 0)
    end
    module_function :uri_part_of

    def uri_dirname(uri)
      uri = uri.clone
      uri.path = uri.path.sub(/\/[^\/]*\z/, '/')
      uri
    end
    module_function :uri_dirname

    def hash_find_value(hash)
      hash.each do |k, v|
        return v if yield(k, v)
      end
      nil
    end
    module_function :hash_find_value

    def parse_challenge_param(param_str)
      param = {}
      param_str.scan(/\s*([^\,]+(?:\\.[^\,]*)*)/).each do |str|
        key, value = str[0].scan(/\A([^=]+)=(.*)\z/)[0]
        if /\A"(.*)"\z/ =~ value
          value = $1.gsub(/\\(.)/, '\1')
        end
        param[key] = value
      end
      param
    end
    module_function :parse_challenge_param
  end


end
