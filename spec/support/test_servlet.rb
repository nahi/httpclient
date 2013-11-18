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