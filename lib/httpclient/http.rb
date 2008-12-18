# HTTPClient - HTTP client library.
# Copyright (C) 2000-2008  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.

# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


require 'time'


module HTTP


  module Status
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NON_AUTHORITATIVE_INFORMATION = 203
    NO_CONTENT = 204
    RESET_CONTENT = 205
    PARTIAL_CONTENT = 206
    MOVED_PERMANENTLY = 301
    FOUND = 302
    SEE_OTHER = 303
    TEMPORARY_REDIRECT = MOVED_TEMPORARILY = 307
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PROXY_AUTHENTICATE_REQUIRED = 407
    INTERNAL = 500

    SUCCESSFUL_STATUS = [
      OK, CREATED, ACCEPTED,
      NON_AUTHORITATIVE_INFORMATION, NO_CONTENT,
      RESET_CONTENT, PARTIAL_CONTENT
    ]

    REDIRECT_STATUS = [
      MOVED_PERMANENTLY, FOUND, SEE_OTHER,
      TEMPORARY_REDIRECT, MOVED_TEMPORARILY
    ]

    def self.successful?(status)
      SUCCESSFUL_STATUS.include?(status)
    end

    def self.redirect?(status)
      REDIRECT_STATUS.include?(status)
    end
  end


  class << self
    def http_date(a_time)
      a_time.gmtime.strftime("%a, %d %b %Y %H:%M:%S GMT")
    end

    def keep_alive_enabled?(version)
      version >= 1.1
    end
  end


  # HTTP::Message -- HTTP message.
  # 
  # DESCRIPTION
  #   A class that describes 1 HTTP request / response message.
  #
  class Message

    CRLF = "\r\n"

    attr_reader :header

    attr_reader :body

    attr_accessor :peer_cert

    # HTTP::Message::Headers -- HTTP message header.
    # 
    # DESCRIPTION
    #   A class that describes header part of HTTP message.
    #
    class Headers
      # HTTP version string in a HTTP header.
      attr_accessor :http_version
      # Content-type.
      attr_accessor :body_type
      # Charset.
      attr_accessor :body_charset
      # Size of body.
      attr_reader :body_size
      # A milestone of body.
      attr_accessor :body_date
      # Chunked or not.
      attr_reader :chunked
      # Request method.
      attr_reader :request_method
      # Requested URI.
      attr_reader :request_uri
      # HTTP status reason phrase.
      attr_accessor :reason_phrase

      attr_accessor :request_via_proxy

      attr_reader :response_status_code

      StatusCodeMap = {
        Status::OK => 'OK',
        Status::CREATED => "Created",
        Status::NON_AUTHORITATIVE_INFORMATION => "Non-Authoritative Information",
        Status::NO_CONTENT => "No Content",
        Status::RESET_CONTENT => "Reset Content",
        Status::PARTIAL_CONTENT => "Partial Content",
        Status::MOVED_PERMANENTLY => 'Moved Permanently',
        Status::FOUND => 'Found',
        Status::SEE_OTHER => 'See Other',
        Status::TEMPORARY_REDIRECT => 'Temporary Redirect',
        Status::MOVED_TEMPORARILY => 'Temporary Redirect',
        Status::BAD_REQUEST => 'Bad Request',
        Status::INTERNAL => 'Internal Server Error',
      }

      CharsetMap = {
        'NONE' => 'us-ascii',
        'EUC'  => 'euc-jp',
        'SJIS' => 'shift_jis',
        'UTF8' => 'utf-8',
      }

      # SYNOPSIS
      #   HTTP::Message.new
      #
      # ARGS
      #   N/A
      #
      # DESCRIPTION
      #   Create a instance of HTTP request or HTTP response.  Specify
      #   status_code for HTTP response.
      #
      def initialize
        @is_request = nil	# true, false and nil
        @http_version = 1.1
        @body_type = nil
        @body_charset = nil
        @body_size = nil
        @body_date = nil
        @header_item = []
        @chunked = false
        @response_status_code = nil
        @reason_phrase = nil
        @request_method = nil
        @request_uri = nil
        @request_query = nil
        @request_via_proxy = nil
      end

      def init_connect_request(uri, hostport)
        @is_request = true
        @request_method = 'CONNECT'
        @request_uri = uri
        @request_query = hostport
        @http_version = 1.0
      end

      NIL_URI = URI.parse('http://nil-uri-given/')
      def init_request(method, uri, query = nil)
        @is_request = true
        @request_method = method
        @request_uri = uri || NIL_URI
        @request_query = create_query_uri(@request_uri, query)
        @request_via_proxy = false
      end

      def init_response(status_code)
        @is_request = false
        self.response_status_code = status_code
      end

      def response_status_code=(status_code)
        @response_status_code = status_code
        @reason_phrase = StatusCodeMap[@response_status_code]
      end

      def contenttype
        self['content-type'][0]
      end

      def contenttype=(contenttype)
        self['content-type'] = contenttype
      end

      # body_size == nil means that the body is_a? IO
      def body_size=(body_size)
        @body_size = body_size
        if @body_size
          @chunked = false
        else
          @chunked = true
        end
      end

      def dump(dev = nil)
        set_header
        str = nil
        if @is_request
          str = request_line
        else
          str = response_status_line
        end
        str += @header_item.collect { |key, value|
          dump_line("#{ key }: #{ value }")
        }.join
        if dev
          dev << str
          dev
        else
          str
        end
      end

      def set(key, value)
        @header_item.push([key, value])
      end

      def get(key = nil)
        if key.nil?
          @header_item
        else
          key = key.upcase
          @header_item.find_all { |pair| pair[0].upcase == key }
        end
      end

      def delete(key)
        key = key.upcase
        @header_item.delete_if { |k, v| k.upcase == key }
      end

      def []=(key, value)
        set(key, value)
      end

      def [](key)
        get(key).collect { |item| item[1] }
      end

    private

      def request_line
        path = if @request_via_proxy
            if @request_uri.port
              "#{ @request_uri.scheme }://#{ @request_uri.host }:#{ @request_uri.port }#{ @request_query }"
            else
              "#{ @request_uri.scheme }://#{ @request_uri.host }#{ @request_query }"
            end
          else
            @request_query
          end
        dump_line("#{ @request_method } #{ path } HTTP/#{ @http_version }")
      end

      def response_status_line
        if defined?(Apache)
          dump_line("HTTP/#{ @http_version } #{ response_status_code } #{ @reason_phrase }")
        else
          dump_line("Status: #{ response_status_code } #{ @reason_phrase }")
        end
      end

      def set_header
        if defined?(Apache) && !self['Date']
          set('Date', HTTP.http_date(Time.now))
        end

        keep_alive = HTTP.keep_alive_enabled?(@http_version)
        set('Connection', 'close') unless keep_alive

        if @chunked
          set('Transfer-Encoding', 'chunked')
        else
          if keep_alive or @body_size != 0
            set('Content-Length', @body_size.to_s)
          end
        end

        if @body_date
          set('Last-Modified', HTTP.http_date(@body_date))
        end

        if @is_request == true
          if @http_version >= 1.1
            if @request_uri.port == @request_uri.default_port
              set('Host', "#{@request_uri.host}")
            else
              set('Host', "#{@request_uri.host}:#{@request_uri.port}")
            end
          end
        elsif @is_request == false
          set('Content-Type', "#{ @body_type || 'text/html' }; charset=#{ CharsetMap[@body_charset || $KCODE] }")
        end
      end

      def dump_line(str)
        str + CRLF
      end

      def create_query_uri(uri, query)
        path = uri.path
        path = '/' if path.nil? or path.empty?
        query_str = nil
        if uri.query
          query_str = uri.query
        end
        if query
          if query_str
            query_str << '&' << Message.create_query_part_str(query)
          else
            query_str = Message.create_query_part_str(query)
          end
        end
        if query_str
          path += "?#{query_str}"
        end
        path
      end
    end

    class Body
      attr_reader :size
      attr_accessor :chunk_size

      def initialize(body = nil, boundary = nil)
        @body = nil
        @size = nil
        @positions = {}
        @boundary = boundary
        set_content(body, boundary)
        @chunk_size = 1024 * 16
      end

      def dump(header = '', dev = '')
        if @body.respond_to?(:read)
          dev << header
          reset_pos(@body)
          dump_chunks(@body, dev)
          dev << (dump_last_chunk + CRLF)
        elsif @body.is_a?(Parts)
          dev << header
          buf = ''
          @body.parts.each do |part|
            if Parts.file?(part)
              reset_pos(part)
              while !part.read(@chunk_size, buf).nil?
                dev << buf
              end
            else
              dev << part
            end
          end
        elsif @body
          dev << header + @body
        else
          dev << header
        end
        dev
      end

      def content
        @body
      end

      def set_content(body, boundary = nil)
        if body.nil?
          @body = nil
          @size = nil
        elsif body.respond_to?(:read)
          # uses Transfer-Encoding: chunked.  bear in mind that server may not
          # support it.  at least ruby's CGI doesn't.
          @body = body
          remember_pos(@body)
          @size = nil
        elsif boundary and Message.multiparam_query?(body)
          @body = build_query_multipart_str(body, boundary)
          @size = @body.size
        else
          @body = Message.create_query_part_str(body)
          @size = @body.size
        end
      end

    private

      def remember_pos(io)
        # IO may not support it (ex. IO.pipe)
        @positions[io] = io.pos rescue nil
      end

      def reset_pos(io)
        io.pos = @positions[io] if @positions.key?(io)
      end

      def dump_chunks(io, dev)
        buf = ''
        while !io.read(@chunk_size, buf).nil?
          dev << dump_chunk(buf)
        end
      end

      def dump_chunk(str)
        dump_chunk_size(str.size) + (str + CRLF)
      end

      def dump_last_chunk
        dump_chunk_size(0)
      end

      def dump_chunk_size(size)
        sprintf("%x", size) + CRLF
      end

      class Parts
        attr_reader :size

        def self.file?(obj)
          obj.respond_to?(:path) and obj.respond_to?(:pos) and obj.respond_to?(:pos=)
        end

        def initialize
          @body = []
          @size = 0
          @as_stream = false
        end

        def add(part)
          if Parts.file?(part)
            @as_stream = true
            @body << part
            if part.respond_to?(:size)
              @size += part.size
            elsif part.respond_to?(:lstat)
              @size += part.lstat.size
            else
              # use chunked upload
              @size = nil
            end
          elsif @body[-1].is_a?(String)
            @body[-1] += part.to_s
            @size += part.to_s.size if @size
          else
            @body << part.to_s
            @size += part.to_s.size if @size
          end
        end

        def parts
          if @as_stream
            @body
          else
            [@body.join]
          end
        end
      end

      def build_query_multipart_str(query, boundary)
        parts = Parts.new
        query.each do |attr, value|
          value ||= ''
          extra_content_disposition = content_type = content = nil
          if Parts.file?(value)
            remember_pos(value)
            params = {}
            params['filename'] = File.basename(value.path)
            # Creation time is not available from File::Stat
            params['modification-date'] = value.mtime.rfc822 if params.respond_to?(:mtime)
            params['read-date'] = value.atime.rfc822 if params.respond_to?(:atime)
            param_str = params.to_a.collect { |k, v|
              "#{k}=\"#{v}\""
            }.join("; ")
            extra_content_disposition = " #{param_str}"
            content_type = mime_type(value.path)
          else
            extra_content_disposition = ''
            content_type = mime_type(nil)
          end
          parts.add("--#{boundary}" + CRLF +
            %{Content-Disposition: form-data; name="#{attr.to_s}";} +
            extra_content_disposition + CRLF +
            "Content-Type: " + content_type + CRLF + CRLF)
          parts.add(value)
          parts.add(CRLF)
        end
        parts.add("--#{boundary}--" + CRLF + CRLF) # empty epilogue
        parts
      end

      @@mime_type_func = nil

      def set_mime_type_func(val)
        @@mime_type_func = val
      end

      def get_mime_type_func
        @@mime_type_func
      end

      def mime_type(path)
        if @@mime_type_func
          res = @@mime_type_func.call(path)
          if !res || res.to_s == ''
            return 'application/octet-stream'
          else
            return res
          end
        else
          internal_mime_type(path)
        end
      end

      def internal_mime_type(path)
        case path
        when /\.txt$/i
          'text/plain'
        when /\.(htm|html)$/i
          'text/html'
        when /\.doc$/i
          'application/msword'
        when /\.png$/i
          'image/png'
        when /\.gif$/i
          'image/gif'
        when /\.(jpg|jpeg)$/i
          'image/jpeg'
        else
          'application/octet-stream'
        end
      end
    end

    def initialize
      @header = Headers.new
      @body = @peer_cert = nil
    end

    class << self
      alias __new new
      undef new
    end

    def self.new_connect_request(uri, hostport)
      m = self.__new
      m.header.init_connect_request(uri, hostport)
      m
    end

    def self.new_request(method, uri, query = nil, body = nil, boundary = nil)
      m = self.__new
      m.header.init_request(method, uri, query)
      m.body = Body.new(body || '', boundary)
      m
    end

    def self.new_response(body = '')
      m = self.__new
      m.header.init_response(Status::OK)
      m.body = Body.new(body)
      m
    end

    def dump(dev = '')
      str = header.dump + CRLF
      if body
        dev = body.dump(str, dev)
      else
        dev << str
      end
      dev
    end

    def load(str)
      buf = str.dup
      unless self.header.load(buf)
        self.body.load(buf)
      end
    end

    def header=(header)
      @header = header
    end

    def content
      @body.content
    end

    def body=(body)
      @body = body
      @header.body_size = @body.size if @header
    end

    def status
      @header.response_status_code
    end

    alias code status
    alias status_code status

    def status=(status)
      @header.response_status_code = status
    end

    def version
      @header.http_version
    end

    def version=(version)
      @header.http_version = version
    end

    def reason
      @header.reason_phrase
    end

    def reason=(reason)
      @header.reason_phrase = reason
    end

    def contenttype
      @header.contenttype
    end

    def contenttype=(contenttype)
      @header.contenttype = contenttype
    end

    class << self
      def create_query_part_str(query)
        if multiparam_query?(query)
          escape_query(query)
        elsif query.respond_to?(:read)
          query = query.read
        else
          query.to_s
        end
      end

      def multiparam_query?(query)
        query.is_a?(Array) or query.is_a?(Hash)
      end

      def escape_query(query)
        query.collect { |attr, value|
          if value.respond_to?(:read)
            value = value.read
          end
          escape(attr.to_s) << '=' << escape(value.to_s)
        }.join('&')
      end

      # from CGI.escape
      def escape(str)
        str.gsub(/([^ a-zA-Z0-9_.-]+)/n) {
          '%' + $1.unpack('H2' * $1.size).join('%').upcase
        }.tr(' ', '+')
      end
    end
  end


end
