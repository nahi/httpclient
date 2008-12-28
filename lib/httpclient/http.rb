# HTTPClient - HTTP client library.
# Copyright (C) 2000-2008  NAKAMURA, Hiroshi  <nahi@ruby-lang.org>.
#
# This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
# redistribute it and/or modify it under the same terms of Ruby's license;
# either the dual license version in 2003, or any later version.


require 'time'


module HTTP


  # Represents HTTP response status.  Defines constants for HTTP response and
  # some conditional methods.
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

    # Returns true if the given status represents successful HTTP response.
    # See also SUCCESSFUL_STATUS.
    def self.successful?(status)
      SUCCESSFUL_STATUS.include?(status)
    end

    # Returns true if the given status is thought to be redirec.
    # See also REDIRECT_STATUS.
    def self.redirect?(status)
      REDIRECT_STATUS.include?(status)
    end
  end


  class << self
    # Returns true if the given HTTP version allows keep alive connection.
    # version:: Float
    def keep_alive_enabled?(version)
      version >= 1.1
    end
  end


  # Represents a HTTP message.  A message is for a request or a response.
  #
  # Some attributes are only for a request or a response, not both.
  #
  # Request message is generated from given parameters internally so users
  # don't need to care about it.  Response message is the instance that
  # methods of HTTPClient returns so users need to know how to extract
  # HTTP response data from Message.
  class Message

    CRLF = "\r\n"

    # HTTP::Message::Headers:: message header.
    attr_reader :header

    # HTTP::Message::Body:: message body.
    attr_reader :body

    # OpenSSL::X509::Certificate:: response only.  server certificate which is
    #                              used for retrieving the response.
    attr_accessor :peer_cert

    # Represents HTTP message header.
    class Headers
      # HTTP version in a HTTP header.  Float.
      attr_accessor :http_version
      # Size of body.  nil when size is unknown (e.g. chunked response).
      attr_reader :body_size
      # Request/Response is chunked or not.
      attr_accessor :chunked

      # Request only.  Requested method.
      attr_reader :request_method
      # Request only.  Requested URI.
      attr_accessor :request_uri
      # Request only.  Requested query.
      attr_accessor :request_query
      # Request only.  Requested via proxy or not.
      attr_accessor :request_via_proxy

      # Response only.  HTTP status
      attr_reader :status_code
      # Response only.  HTTP status reason phrase.
      attr_accessor :reason_phrase

      # Used for dumping response.
      attr_accessor :body_type # :nodoc:
      # Used for dumping response.
      attr_accessor :body_charset # :nodoc:
      # Used for dumping response.
      attr_accessor :body_date # :nodoc:

      # HTTP response status code to reason phrase mapping definition.
      STATUS_CODE_MAP = {
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

      # $KCODE to charset mapping definition.
      CHARSET_MAP = {
        'NONE' => 'us-ascii',
        'EUC'  => 'euc-jp',
        'SJIS' => 'shift_jis',
        'UTF8' => 'utf-8',
      }

      # Creates a Message::Headers.  Use init_request, init_response, or
      # init_connect_request for acutual initialize.
      def initialize
        @http_version = 1.1
        @body_size = nil
        @chunked = false

        @request_method = nil
        @request_uri = nil
        @request_query = nil
        @request_via_proxy = nil

        @status_code = nil
        @reason_phrase = nil

        @body_type = nil
        @body_charset = nil
        @body_date = nil

        @is_request = nil
        @header_item = []
        @dumped = false
      end

      # Initialize this instance as CONNECT request.
      def init_connect_request(uri, hostport)
        @is_request = true
        @request_method = 'CONNECT'
        @request_uri = uri
        @request_query = hostport
        @http_version = 1.0
      end

      # Placeholder URI object for nil uri.
      NIL_URI = URI.parse('http://nil-uri-given/')
      # Initialize this instance as a general request.
      def init_request(method, uri, query = nil)
        @is_request = true
        @request_method = method
        @request_uri = uri || NIL_URI
        @request_query = query
        @request_via_proxy = false
      end

      # Initialize this instance as a resopnse.
      def init_response(status_code)
        @is_request = false
        self.status_code = status_code
      end

      # Sets status code and reason phrase.
      def status_code=(status_code)
        @status_code = status_code
        @reason_phrase = STATUS_CODE_MAP[@status_code]
      end

      # Returns 'Content-Type' header value.
      def contenttype
        self['Content-Type'][0]
      end

      # Sets 'Content-Type' header value.  Overrides if already exists.
      def contenttype=(contenttype)
        delete('Content-Type')
        self['Content-Type'] = contenttype
      end

      # Sets byte size of message body.
      # body_size == nil means that the body is_a? IO
      def body_size=(body_size)
        @body_size = body_size
      end

      # Dumps this Header and returns a dumped String.
      def dump
        set_header
        str = nil
        if @is_request
          str = request_line
        else
          str = response_status_line
        end
        str + @header_item.collect { |key, value|
          "#{ key }: #{ value }#{ CRLF }"
        }.join
      end

      # Adds a header.  Addition order is preserved.
      def set(key, value)
        @header_item.push([key, value])
      end

      # Returns an Array of headers for the given key.  Each element is a pair
      # of key and value.  It returns an single element Array even if the only
      # one header exists.  If nil key given, it returns all headers.
      def get(key = nil)
        if key.nil?
          all
        else
          key = key.upcase
          @header_item.find_all { |k, v| k.upcase == key }
        end
      end

      # Returns an Array of all headers.
      def all
        @header_item
      end

      # Deletes headers of the given key.
      def delete(key)
        key = key.upcase
        @header_item.delete_if { |k, v| k.upcase == key }
      end

      # Adds a header.  See set.
      def []=(key, value)
        set(key, value)
      end

      # Returns an Array of header values for the given key.
      def [](key)
        get(key).collect { |item| item[1] }
      end

    private

      def request_line
        path = create_query_uri(@request_uri, @request_query)
        if @request_via_proxy
          path = "#{ @request_uri.scheme }://#{ @request_uri.host }:#{ @request_uri.port }#{ path }"
        end
        "#{ @request_method } #{ path } HTTP/#{ @http_version }#{ CRLF }"
      end

      def response_status_line
        if defined?(Apache)
          "HTTP/#{ @http_version } #{ @status_code } #{ @reason_phrase }#{ CRLF }"
        else
          "Status: #{ @status_code } #{ @reason_phrase }#{ CRLF }"
        end
      end

      def set_header
        if @is_request
          set_request_header
        else
          set_response_header
        end
      end

      def set_request_header
        return if @dumped
        @dumped = true
        keep_alive = HTTP.keep_alive_enabled?(@http_version)
        if !keep_alive and @request_method != 'CONNECT'
          set('Connection', 'close')
        end
        if @chunked
          set('Transfer-Encoding', 'chunked')
        elsif keep_alive or @body_size != 0
          set('Content-Length', @body_size.to_s)
        end
        if @http_version >= 1.1
	  set('Host', "#{@request_uri.host}:#{@request_uri.port}")
        end
      end

      def set_response_header
        return if @dumped
        @dumped = true
        if defined?(Apache) && self['Date'].empty?
          set('Date', Time.now.httpdate)
        end
        keep_alive = HTTP.keep_alive_enabled?(@http_version)
        if @chunked
          set('Transfer-Encoding', 'chunked')
        else
          if keep_alive or @body_size != 0
            set('Content-Length', @body_size.to_s)
          end
        end
        if @body_date
          set('Last-Modified', @body_date.httpdate)
        end
        if self['Content-Type'].empty?
          set('Content-Type', "#{ @body_type || 'text/html' }; charset=#{ charset_label(@body_charset || $KCODE) }")
        end
      end

      def charset_label(charset)
        CHARSET_MAP[charset] || 'us-ascii'
      end

      def create_query_uri(uri, query)
        if @request_method == 'CONNECT'
          return query
        end
        path = uri.path
        path = '/' if path.nil? or path.empty?
        query_str = nil
        if uri.query
          query_str = uri.query
        end
        if query
          if query_str
            query_str += "&#{Message.create_query_part_str(query)}"
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

    # Represents HTTP message body.
    class Body
      # Size of body.  nil when size is unknown (e.g. chunked response).
      attr_reader :size
      # maxbytes of IO#read for streaming request.  See DEFAULT_CHUNK_SIZE.
      attr_accessor :chunk_size

      # Default value for chunk_size
      DEFAULT_CHUNK_SIZE = 1024 * 16

      # Creates a Message::Body.  Use init_request or init_response
      # for acutual initialize.
      def initialize
        @body = nil
        @size = nil
        @positions = nil
        @chunk_size = nil
      end

      # Initialize this instance as a request.
      def init_request(body = nil, boundary = nil)
        @boundary = boundary
        @positions = {}
        set_content(body, boundary)
        @chunk_size = DEFAULT_CHUNK_SIZE
      end

      # Initialize this instance as a response.
      def init_response(body = nil)
        @body = body
        if @body.respond_to?(:size)
          @size = @body.size
        else
          @size = nil
        end
      end

      def dump_chunked(header = '', dev = '')
        dev << header
        if @body.is_a?(Parts)
          @body.parts.each do |part|
            if Message.file?(part)
              reset_pos(part)
              dump_chunks(part, dev)
            else
              dev << dump_chunk(part)
            end
          end
          dev << (dump_last_chunk + CRLF)
        elsif @body
          reset_pos(@body)
          dump_chunks(@body, dev)
          dev << (dump_last_chunk + CRLF)
        end
        dev
      end

      def dump(header = '', dev = '')
        if @body.is_a?(Parts)
          dev << header
          buf = ''
          @body.parts.each do |part|
            if Message.file?(part)
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

    private

      def set_content(body, boundary = nil)
        if body.respond_to?(:read)
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

        def initialize
          @body = []
          @size = 0
          @as_stream = false
        end

        def add(part)
          if Message.file?(part)
            @as_stream = true
            @body << part
            if part.respond_to?(:size)
              if sz = part.size
                @size += sz
              else
                @size = nil
              end
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
          headers = ["--#{boundary}"]
          if Message.file?(value)
            remember_pos(value)
            param_str = params_from_file(value).collect { |k, v|
              "#{k}=\"#{v}\""
            }.join("; ")
            if value.respond_to?(:mime_type)
              content_type = value.mime_type
            else
              content_type = Message.mime_type(value.path)
            end
            headers << %{Content-Disposition: form-data; name="#{attr}"; #{param_str}}
            headers << %{Content-Type: #{content_type}}
          else
            headers << %{Content-Disposition: form-data; name="#{attr}"}
          end
          parts.add(headers.join(CRLF) + CRLF + CRLF)
          parts.add(value)
          parts.add(CRLF)
        end
        parts.add("--#{boundary}--" + CRLF + CRLF) # empty epilogue
        parts
      end

      def params_from_file(value)
        params = {}
        params['filename'] = File.basename(value.path || '')
        # Creation time is not available from File::Stat
        if value.respond_to?(:mtime)
          params['modification-date'] = value.mtime.rfc822
        end
        if value.respond_to?(:atime)
          params['read-date'] = value.atime.rfc822
        end
        params
      end
    end

    def initialize
      @header = Headers.new
      @body = @peer_cert = nil
    end

    def self.new_connect_request(uri, hostport)
      m = self.new
      m.header.init_connect_request(uri, hostport)
      m.header.body_size = 0
      m
    end

    def self.new_request(method, uri, query = nil, body = nil, boundary = nil)
      m = self.new
      m.header.init_request(method, uri, query)
      m.body = Body.new
      m.body.init_request(body || '', boundary)
      m.header.body_size = m.body.size
      m.header.chunked = true if m.body.size.nil?
      m
    end

    def self.new_response(body)
      m = self.new
      m.header.init_response(Status::OK)
      m.body = Body.new
      m.body.init_response(body)
      m.header.body_size = m.body.size || 0
      m
    end

    def dump(dev = '')
      str = header.dump + CRLF
      if header.chunked
        dev = body.dump_chunked(str, dev)
      elsif body
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
      @header.status_code
    end

    alias code status
    alias status_code status

    def status=(status)
      @header.status_code = status
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

      def file?(obj)
        obj.respond_to?(:path) and obj.respond_to?(:pos) and obj.respond_to?(:pos=)
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
