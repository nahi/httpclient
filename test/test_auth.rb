require File.expand_path('helper', File.dirname(__FILE__))
require 'digest/md5'

class TestAuth < Test::Unit::TestCase
  include Helper

  def setup
    super
    setup_server
  end

  def teardown
    super
  end

  def setup_server
    @server = WEBrick::HTTPServer.new(
      :BindAddress => "localhost",
      :Logger => @logger,
      :Port => 0,
      :AccessLog => [],
      :DocumentRoot => File.dirname(File.expand_path(__FILE__))
    )
    @serverport = @server.config[:Port]
    @server.mount(
      '/basic_auth',
      WEBrick::HTTPServlet::ProcHandler.new(method(:do_basic_auth).to_proc)
    )
    @server.mount(
      '/digest_auth',
      WEBrick::HTTPServlet::ProcHandler.new(method(:do_digest_auth).to_proc)
    )
    @server.mount(
      '/digest_sess_auth',
      WEBrick::HTTPServlet::ProcHandler.new(method(:do_digest_sess_auth).to_proc)
    )
    htpasswd = File.join(File.dirname(__FILE__), 'htpasswd')
    htpasswd_userdb = WEBrick::HTTPAuth::Htpasswd.new(htpasswd)
    htdigest = File.join(File.dirname(__FILE__), 'htdigest')
    htdigest_userdb = WEBrick::HTTPAuth::Htdigest.new(htdigest)
    @basic_auth = WEBrick::HTTPAuth::BasicAuth.new(
      :Logger => @logger,
      :Realm => 'auth',
      :UserDB => htpasswd_userdb
    )
    @digest_auth = WEBrick::HTTPAuth::DigestAuth.new(
      :Logger => @logger,
      :Algorithm => 'MD5',
      :Realm => 'auth',
      :UserDB => htdigest_userdb
    )
    @digest_sess_auth = WEBrick::HTTPAuth::DigestAuth.new(
      :Logger => @logger,
      :Algorithm => 'MD5-sess',
      :Realm => 'auth',
      :UserDB => htdigest_userdb
    )
    @server_thread = start_server_thread(@server)

    @proxy_digest_auth = WEBrick::HTTPAuth::ProxyDigestAuth.new(
      :Logger => @proxylogger,
      :Algorithm => 'MD5',
      :Realm => 'auth',
      :UserDB => htdigest_userdb
    )

    @proxyserver = WEBrick::HTTPProxyServer.new(
      :ProxyAuthProc => @proxy_digest_auth.method(:authenticate).to_proc,
      :BindAddress => "localhost",
      :Logger => @proxylogger,
      :Port => 0,
      :AccessLog => []
    )
    @proxyport = @proxyserver.config[:Port]
    @proxyserver_thread = start_server_thread(@proxyserver)
  end

  def do_basic_auth(req, res)
    @basic_auth.authenticate(req, res)
    res['content-type'] = 'text/plain'
    res.body = 'basic_auth OK'
  end

  def do_digest_auth(req, res)
    @digest_auth.authenticate(req, res)
    res['content-type'] = 'text/plain'
    res['x-query'] = req.body
    res.body = 'digest_auth OK' + req.query_string.to_s
  end

  def do_digest_sess_auth(req, res)
    @digest_sess_auth.authenticate(req, res)
    res['content-type'] = 'text/plain'
    res['x-query'] = req.body
    res.body = 'digest_sess_auth OK' + req.query_string.to_s
  end

  def test_basic_auth
    c = HTTPClient.new
    c.set_auth("http://localhost:#{serverport}/", 'admin', 'admin')
    assert_equal('basic_auth OK', c.get_content("http://localhost:#{serverport}/basic_auth"))
  end

  def test_basic_auth_compat
    c = HTTPClient.new
    c.set_basic_auth("http://localhost:#{serverport}/", 'admin', 'admin')
    assert_equal('basic_auth OK', c.get_content("http://localhost:#{serverport}/basic_auth"))
  end

  def test_BASIC_auth
    c = HTTPClient.new
    webrick_backup = @basic_auth.instance_eval { @auth_scheme }
    #httpaccess2_backup = c.www_auth.basic_auth.instance_eval { @scheme }
    begin
      @basic_auth.instance_eval { @auth_scheme = "BASIC" }
      c.www_auth.basic_auth.instance_eval { @scheme = "BASIC" }
      c.set_auth("http://localhost:#{serverport}/", 'admin', 'admin')
      assert_equal('basic_auth OK', c.get_content("http://localhost:#{serverport}/basic_auth"))
    ensure
      @basic_auth.instance_eval { @auth_scheme = webrick_backup }
      #c.www_auth.basic_auth.instance_eval { @scheme = httpaccess2_backup }
    end
  end

  def test_basic_auth_reuses_credentials
    c = HTTPClient.new
    c.set_auth("http://localhost:#{serverport}/", 'admin', 'admin')
    assert_equal('basic_auth OK', c.get_content("http://localhost:#{serverport}/basic_auth/"))
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.debug_dev = str = ''
    c.get_content("http://localhost:#{serverport}/basic_auth/sub/dir/")
    assert_match /Authorization: Basic YWRtaW46YWRtaW4=/, str
  end

  def test_digest_auth
    c = HTTPClient.new
    c.set_auth("http://localhost:#{serverport}/", 'admin', 'admin')
    assert_equal('digest_auth OK', c.get_content("http://localhost:#{serverport}/digest_auth"))
  end

  def test_digest_auth_reuses_credentials
    c = HTTPClient.new
    c.set_auth("http://localhost:#{serverport}/", 'admin', 'admin')
    assert_equal('digest_auth OK', c.get_content("http://localhost:#{serverport}/digest_auth/"))
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.debug_dev = str = ''
    c.get_content("http://localhost:#{serverport}/digest_auth/sub/dir/")
    assert_match /Authorization: Digest/, str
  end

  def test_digest_auth_with_block
    c = HTTPClient.new
    c.set_auth("http://localhost:#{serverport}/", 'admin', 'admin')
    called = false
    c.get_content("http://localhost:#{serverport}/digest_auth") do |str|
      assert_equal('digest_auth OK', str)
      called = true
    end
    assert(called)
    #
    called = false
    c.get("http://localhost:#{serverport}/digest_auth") do |str|
      assert_equal('digest_auth OK', str)
      called = true
    end
    assert(called)
  end

  def test_digest_auth_with_post_io
    c = HTTPClient.new
    c.set_auth("http://localhost:#{serverport}/", 'admin', 'admin')
    post_body = StringIO.new("1234567890")
    assert_equal('1234567890', c.post("http://localhost:#{serverport}/digest_auth", post_body).header['x-query'][0])
    #
    post_body = StringIO.new("1234567890")
    post_body.read(5)
    assert_equal('67890', c.post("http://localhost:#{serverport}/digest_auth", post_body).header['x-query'][0])
  end

  def test_digest_auth_with_querystring
    c = HTTPClient.new
    c.debug_dev = STDERR if $DEBUG
    c.set_auth("http://localhost:#{serverport}/", 'admin', 'admin')
    assert_equal('digest_auth OKbar=baz', c.get_content("http://localhost:#{serverport}/digest_auth/foo?bar=baz"))
  end

  def test_perfer_digest
    c = HTTPClient.new
    c.set_auth('http://example.com/', 'admin', 'admin')
    c.test_loopback_http_response << "HTTP/1.0 401 Unauthorized\nWWW-Authenticate: Basic realm=\"foo\"\nWWW-Authenticate: Digest realm=\"foo\", nonce=\"nonce\", stale=false\nContent-Length: 2\n\nNG"
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.debug_dev = str = ''
    c.get_content('http://example.com/')
    assert_match(/^Authorization: Digest/, str)
  end

  def test_digest_sess_auth
    c = HTTPClient.new
    c.set_auth("http://localhost:#{serverport}/", 'admin', 'admin')
    assert_equal('digest_sess_auth OK', c.get_content("http://localhost:#{serverport}/digest_sess_auth"))
  end

  def test_proxy_auth
    c = HTTPClient.new
    c.set_proxy_auth('admin', 'admin')
    c.test_loopback_http_response << "HTTP/1.0 407 Unauthorized\nProxy-Authenticate: Basic realm=\"foo\"\nContent-Length: 2\n\nNG"
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.debug_dev = str = ''
    c.get_content('http://example.com/')
    assert_match(/Proxy-Authorization: Basic YWRtaW46YWRtaW4=/, str)
  end

  def test_proxy_auth_reuses_credentials
    c = HTTPClient.new
    c.set_proxy_auth('admin', 'admin')
    c.test_loopback_http_response << "HTTP/1.0 407 Unauthorized\nProxy-Authenticate: Basic realm=\"foo\"\nContent-Length: 2\n\nNG"
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.get_content('http://www1.example.com/')
    c.debug_dev = str = ''
    c.get_content('http://www2.example.com/')
    assert_match(/Proxy-Authorization: Basic YWRtaW46YWRtaW4=/, str)
  end

  def test_digest_proxy_auth_loop
    c = HTTPClient.new
    c.set_proxy_auth('admin', 'admin')
    c.test_loopback_http_response << "HTTP/1.0 407 Unauthorized\nProxy-Authenticate: Digest realm=\"foo\", nonce=\"nonce\", stale=false\nContent-Length: 2\n\nNG"
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    md5 = Digest::MD5.new
    ha1 = md5.hexdigest("admin:foo:admin")
    ha2 = md5.hexdigest("GET:/")
    response = md5.hexdigest("#{ha1}:nonce:#{ha2}")
    c.debug_dev = str = ''
    c.get_content('http://example.com/')
    assert_match(/Proxy-Authorization: Digest/, str)
    assert_match(%r"response=\"#{response}\"", str)
  end

  def test_digest_proxy_auth
    c=HTTPClient.new("http://localhost:#{proxyport}/")
    c.set_proxy_auth('admin', 'admin')
    c.set_auth("http://127.0.0.1:#{serverport}/", 'admin', 'admin')
    assert_equal('basic_auth OK', c.get_content("http://127.0.0.1:#{serverport}/basic_auth"))
  end

  def test_digest_proxy_invalid_auth
    c=HTTPClient.new("http://localhost:#{proxyport}/")
    c.set_proxy_auth('admin', 'wrong')
    c.set_auth("http://127.0.0.1:#{serverport}/", 'admin', 'admin')
    assert_raises(HTTPClient::BadResponseError) do
      c.get_content("http://127.0.0.1:#{serverport}/basic_auth")
    end
  end

  def test_prefer_digest_to_basic_proxy_auth
    c = HTTPClient.new
    c.set_proxy_auth('admin', 'admin')
    c.test_loopback_http_response << "HTTP/1.0 407 Unauthorized\nProxy-Authenticate: Digest realm=\"foo\", nonce=\"nonce\", stale=false\nProxy-Authenticate: Basic realm=\"bar\"\nContent-Length: 2\n\nNG"
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    md5 = Digest::MD5.new
    ha1 = md5.hexdigest("admin:foo:admin")
    ha2 = md5.hexdigest("GET:/")
    response = md5.hexdigest("#{ha1}:nonce:#{ha2}")
    c.debug_dev = str = ''
    c.get_content('http://example.com/')
    assert_match(/Proxy-Authorization: Digest/, str)
    assert_match(%r"response=\"#{response}\"", str)
  end

  def test_digest_proxy_auth_reuses_credentials
    c = HTTPClient.new
    c.set_proxy_auth('admin', 'admin')
    c.test_loopback_http_response << "HTTP/1.0 407 Unauthorized\nProxy-Authenticate: Digest realm=\"foo\", nonce=\"nonce\", stale=false\nContent-Length: 2\n\nNG"
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    md5 = Digest::MD5.new
    ha1 = md5.hexdigest("admin:foo:admin")
    ha2 = md5.hexdigest("GET:/")
    response = md5.hexdigest("#{ha1}:nonce:#{ha2}")
    c.get_content('http://www1.example.com/')
    c.debug_dev = str = ''
    c.get_content('http://www2.example.com/')
    assert_match(/Proxy-Authorization: Digest/, str)
    assert_match(%r"response=\"#{response}\"", str)
  end

  def test_oauth
    c = HTTPClient.new
    config = HTTPClient::OAuth::Config.new(
      :realm => 'http://photos.example.net/',
      :consumer_key => 'dpf43f3p2l4k3l03',
      :consumer_secret => 'kd94hf93k423kf44',
      :token => 'nnch734d00sl2jdk',
      :secret => 'pfkkdhi9sl3r4s00',
      :version => '1.0',
      :signature_method => 'HMAC-SHA1'
    )
    config.debug_timestamp = '1191242096'
    config.debug_nonce = 'kllo9940pd9333jh'
    c.www_auth.oauth.set_config('http://photos.example.net/', config)
    c.www_auth.oauth.challenge('http://photos.example.net/')
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.debug_dev = str = ''
    c.get_content('http://photos.example.net/photos', [[:file, 'vacation.jpg'], [:size, 'original']])
    assert(str.index(%q(GET /photos?file=vacation.jpg&size=original)))
    assert(str.index(%q(Authorization: OAuth realm="http://photos.example.net/", oauth_consumer_key="dpf43f3p2l4k3l03", oauth_nonce="kllo9940pd9333jh", oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1191242096", oauth_token="nnch734d00sl2jdk", oauth_version="1.0")))
    #
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.debug_dev = str = ''
    c.get_content('http://photos.example.net/photos?file=vacation.jpg&size=original')
    assert(str.index(%q(GET /photos?file=vacation.jpg&size=original)))
    assert(str.index(%q(Authorization: OAuth realm="http://photos.example.net/", oauth_consumer_key="dpf43f3p2l4k3l03", oauth_nonce="kllo9940pd9333jh", oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1191242096", oauth_token="nnch734d00sl2jdk", oauth_version="1.0")))
    #
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.debug_dev = str = ''
    c.post_content('http://photos.example.net/photos', [[:file, 'vacation.jpg'], [:size, 'original']])
    assert(str.index(%q(POST /photos)))
    assert(str.index(%q(Authorization: OAuth realm="http://photos.example.net/", oauth_consumer_key="dpf43f3p2l4k3l03", oauth_nonce="kllo9940pd9333jh", oauth_signature="wPkvxykrw%2BBTdCcGqKr%2B3I%2BPsiM%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1191242096", oauth_token="nnch734d00sl2jdk", oauth_version="1.0")))
  end
end
