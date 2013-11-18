class MainServer < BaseServer
  def initialize
    set_logger
    @server = WEBrick::HTTPServer.new(
      :BindAddress => "localhost",
      :Logger => @logger,
      :Port => 0,
      :AccessLog => [],
      :DocumentRoot => File.dirname(File.expand_path(__FILE__))
    )
    [
      :hello, :sleep, :servlet_redirect, :servlet_temporary_redirect, :servlet_see_other,
      :redirect1, :redirect2, :redirect3,
      :redirect_self, :relative_redirect, :redirect_see_other, :chunked,
      :largebody, :status, :compressed, :charset, :continue,
      :servlet_redirect_413, :servlet_413
    ].each do |sym|
      @server.mount(
        "/#{sym}",
        WEBrick::HTTPServlet::ProcHandler.new(method("do_#{sym}").to_proc)
      )
    end
    @server.mount('/servlet', TestServlet.new(@server))
    start
  end

  def escape_noproxy
    backup = HTTPClient::NO_PROXY_HOSTS.dup
    HTTPClient::NO_PROXY_HOSTS.clear
    yield
  ensure
    HTTPClient::NO_PROXY_HOSTS.replace(backup)
  end

  def do_hello(req, res)
    res['content-type'] = 'text/html'
    res.body = "hello"
  end

  def do_sleep(req, res)
    sec = req.query['sec'].to_i
    sleep sec
    res['content-type'] = 'text/html'
    res.body = "hello"
  end

  def do_servlet_redirect(req, res)
    res.set_redirect(WEBrick::HTTPStatus::Found, serverurl + "servlet")
  end

  def do_servlet_redirect_413(req, res)
    res.set_redirect(WEBrick::HTTPStatus::Found, serverurl + "servlet_413")
  end

  def do_servlet_413(req, res)
    res.body = req.body.to_s
  end

  def do_servlet_temporary_redirect(req, res)
    res.set_redirect(WEBrick::HTTPStatus::TemporaryRedirect, serverurl + "servlet")
  end

  def do_servlet_see_other(req, res)
    res.set_redirect(WEBrick::HTTPStatus::SeeOther, serverurl + "servlet")
  end

  def do_redirect1(req, res)
    res.set_redirect(WEBrick::HTTPStatus::MovedPermanently, serverurl + "hello")
  end

  def do_redirect2(req, res)
    res.set_redirect(WEBrick::HTTPStatus::TemporaryRedirect, serverurl + "redirect3")
  end

  def do_redirect3(req, res)
    res.set_redirect(WEBrick::HTTPStatus::Found, serverurl + "hello")
  end

  def do_redirect_self(req, res)
    res.set_redirect(WEBrick::HTTPStatus::Found, serverurl + "redirect_self")
  end

  def do_relative_redirect(req, res)
    res.set_redirect(WEBrick::HTTPStatus::Found, "hello")
  end

  def do_redirect_see_other(req, res)
    if req.request_method == 'POST'
      res.set_redirect(WEBrick::HTTPStatus::SeeOther, serverurl + "redirect_see_other") # self
    else
      res.body = 'hello'
    end
  end

  def do_chunked(req, res)
    res.chunked = true
    res['content-type'] = 'text/plain; charset=UTF-8'
    piper, pipew = IO.pipe
    res.body = piper
    pipew << req.query['msg']
    pipew.close
  end

  def do_largebody(req, res)
    res['content-type'] = 'text/html'
    res.body = "a" * 1000 * 1000
  end

  def do_compressed(req, res)
    res['content-type'] = 'application/octet-stream'
    if req.query['enc'] == 'gzip'
      res['content-encoding'] = 'gzip'
      res.body = GZIP_CONTENT
    elsif req.query['enc'] == 'deflate'
      res['content-encoding'] = 'deflate'
      res.body = DEFLATE_CONTENT
    end
  end

  def do_charset(req, res)
    if RUBY_VERSION > "1.9"
      res.body = 'あいうえお'.encode("euc-jp")
      res['Content-Type'] = 'text/plain; charset=euc-jp'
    else
      res.body = 'this endpoint is for 1.9 or later'
    end
  end

  def do_status(req, res)
    res.status = req.query['status'].to_i
  end

  def do_continue(req, res)
    req.continue
    res.body = 'done!'
  end

  class TestServlet < WEBrick::HTTPServlet::AbstractServlet
    def get_instance(*arg)
      self
    end

    def do_HEAD(req, res)
      res["x-head"] = 'head'    # use this for test purpose only.
      res["x-query"] = query_response(req)
    end

    def do_GET(req, res)
      res.body = 'get'
      res["x-query"] = query_response(req)
    end

    def do_POST(req, res)
      res["content-type"] = "text/plain" # iso-8859-1, not US-ASCII
      res.body = 'post,' + req.body.to_s
      res["x-query"] = body_response(req)
    end

    def do_PUT(req, res)
      res["x-query"] = body_response(req)
      param = WEBrick::HTTPUtils.parse_query(req.body) || {}
      res["x-size"] = (param['txt'] || '').size
      res.body = param['txt'] || 'put'
    end

    def do_DELETE(req, res)
      res.body = 'delete'
    end

    def do_OPTIONS(req, res)
      # check RFC for legal response.
      res.body = 'options'
    end

    def do_PROPFIND(req, res)
      res.body = 'propfind'
    end

    def do_PROPPATCH(req, res)
      res.body = 'proppatch'
      res["x-query"] = body_response(req)
    end

    def do_TRACE(req, res)
      # client SHOULD reflect the message received back to the client as the
      # entity-body of a 200 (OK) response. [RFC2616]
      res.body = 'trace'
      res["x-query"] = query_response(req)
    end

  private

    def query_response(req)
      query_escape(WEBrick::HTTPUtils.parse_query(req.query_string))
    end

    def body_response(req)
      query_escape(WEBrick::HTTPUtils.parse_query(req.body))
    end

    def query_escape(query)
      escaped = []
      query.sort_by { |k, v| k }.collect do |k, v|
        v.to_ary.each do |ve|
          escaped << CGI.escape(k) + '=' + CGI.escape(ve)
        end
      end
      escaped.join('&')
    end
  end
end