# coding: utf-8

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
      :largebody, :status, :compressed, :compressed_large, :charset, :continue,
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
    res.body = "a" * 1_000_000
  end

  def gzip(string)
    wio = StringIO.new("w")
    w_gz = Zlib::GzipWriter.new(wio)
    w_gz.write(string)
    w_gz.close
    compressed = wio.string
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

  def do_compressed_large(req, res)
    res['content-type'] = 'application/octet-stream'
    str = '1234567890' * 100_000
    if req.query['enc'] == 'gzip'
      res['content-encoding'] = 'gzip'
      res.body = gzip(str)
    elsif req.query['enc'] == 'deflate'
      res['content-encoding'] = 'deflate'
      res.body = Zlib::Deflate.deflate(str)
    end
  end

  def do_charset(req, res)
    res.body = 'あいうえお'.encode("euc-jp")
    res['Content-Type'] = 'text/plain; charset=euc-jp'
  end

  def do_status(req, res)
    res.status = req.query['status'].to_i
  end

  def do_continue(req, res)
    req.continue
    res.body = 'done!'
  end
end