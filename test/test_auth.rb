require 'test/unit'
require 'webrick'
require 'logger'
require 'httpclient'


class TestAuth < Test::Unit::TestCase
  Port = 17171

  def setup
    @logger = Logger.new(STDERR)
    @logger.level = Logger::Severity::ERROR
    @url = "http://localhost:#{Port}/"
    @server = nil
    @server_thread = nil
    setup_server
  end

  def teardown
    teardown_server
  end

  def setup_server
    @server = WEBrick::HTTPServer.new(
      :BindAddress => "localhost",
      :Logger => @logger,
      :Port => Port,
      :AccessLog => [],
      :DocumentRoot => File.dirname(File.expand_path(__FILE__))
    )
    @server.mount(
      '/basic_auth',
      WEBrick::HTTPServlet::ProcHandler.new(method(:do_basic_auth).to_proc)
    )
    @server.mount(
      '/digest_auth',
      WEBrick::HTTPServlet::ProcHandler.new(method(:do_digest_auth).to_proc)
    )
    htpasswd = File.join(File.dirname(__FILE__), 'htpasswd')
    htpasswd_userdb = WEBrick::HTTPAuth::Htpasswd.new(htpasswd)
    htdigest = File.join(File.dirname(__FILE__), 'htdigest')
    htdigest_userdb = WEBrick::HTTPAuth::Htdigest.new(htdigest)
    @basic_auth = WEBrick::HTTPAuth::BasicAuth.new(
      :Realm => 'auth',
      :UserDB => htpasswd_userdb
    )
    @digest_auth = WEBrick::HTTPAuth::DigestAuth.new(
      :Algorithm => 'MD5',
      :Realm => 'auth',
      :UserDB => htdigest_userdb
    )
    @server_thread = start_server_thread(@server)
  end

  def start_server_thread(server)
    t = Thread.new {
      Thread.current.abort_on_exception = true
      server.start
    }
    while server.status != :Running
      sleep 0.1
      unless t.alive?
	t.join
	raise
      end
    end
    t
  end

  def teardown_server
    @server.shutdown
    @server_thread.kill
    @server_thread.join
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
    res.body = 'digest_auth OK'
  end

  def test_basic_auth
    c = HTTPClient.new
    c.set_auth("http://localhost:#{Port}/", 'admin', 'admin')
    assert_equal('basic_auth OK', c.get_content("http://localhost:#{Port}/basic_auth"))
  end

  def test_basic_auth_compat
    c = HTTPClient.new
    c.set_basic_auth("http://localhost:#{Port}/", 'admin', 'admin')
    assert_equal('basic_auth OK', c.get_content("http://localhost:#{Port}/basic_auth"))
  end

  def test_BASIC_auth
    c = HTTPClient.new
    webrick_backup = @basic_auth.instance_eval { @auth_scheme }
    #httpaccess2_backup = c.www_auth.basic_auth.instance_eval { @scheme }
    begin
      @basic_auth.instance_eval { @auth_scheme = "BASIC" }
      c.www_auth.basic_auth.instance_eval { @scheme = "BASIC" }
      c.set_auth("http://localhost:#{Port}/", 'admin', 'admin')
      assert_equal('basic_auth OK', c.get_content("http://localhost:#{Port}/basic_auth"))
    ensure
      @basic_auth.instance_eval { @auth_scheme = webrick_backup }
      #c.www_auth.basic_auth.instance_eval { @scheme = httpaccess2_backup }
    end
  end

  def test_digest_auth
    c = HTTPClient.new
    c.set_auth("http://localhost:#{Port}/", 'admin', 'admin')
    assert_equal('digest_auth OK', c.get_content("http://localhost:#{Port}/digest_auth"))
  end

  def test_digest_auth_with_block
    c = HTTPClient.new
    c.set_auth("http://localhost:#{Port}/", 'admin', 'admin')
    called = false
    c.get_content("http://localhost:#{Port}/digest_auth") do |str|
      assert_equal('digest_auth OK', str)
      called = true
    end
    assert(called)
    #
    called = false
    c.get("http://localhost:#{Port}/digest_auth") do |str|
      assert_equal('digest_auth OK', str)
      called = true
    end
    assert(called)
  end

  def test_digest_auth_with_post_io
    c = HTTPClient.new
    c.set_auth("http://localhost:#{Port}/", 'admin', 'admin')
    post_body = StringIO.new("1234567890")
    assert_equal('1234567890', c.post("http://localhost:#{Port}/digest_auth", post_body).header['x-query'][0])
    #
    post_body = StringIO.new("1234567890")
    post_body.read(5)
    assert_equal('67890', c.post("http://localhost:#{Port}/digest_auth", post_body).header['x-query'][0])
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
    c.get_content('http://photos.example.net/photos', :file => 'vacation.jpg', :size => 'original')
    assert(str.index(%q(GET /photos?size=original&file=vacation.jpg)))
    assert(str.index(%q(Authorization: OAuth realm="http://photos.example.net/", oauth_nonce="kllo9940pd9333jh", oauth_timestamp="1191242096", oauth_signature_method="HMAC-SHA1", oauth_token="nnch734d00sl2jdk", oauth_consumer_key="dpf43f3p2l4k3l03", oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D", oauth_version="1.0")))
    #
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.debug_dev = str = ''
    c.get_content('http://photos.example.net/photos?file=vacation.jpg&size=original')
    assert(str.index(%q(GET /photos?file=vacation.jpg&size=original)))
    assert(str.index(%q(Authorization: OAuth realm="http://photos.example.net/", oauth_nonce="kllo9940pd9333jh", oauth_timestamp="1191242096", oauth_signature_method="HMAC-SHA1", oauth_token="nnch734d00sl2jdk", oauth_consumer_key="dpf43f3p2l4k3l03", oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D", oauth_version="1.0")))
    #
    c.test_loopback_http_response << "HTTP/1.0 200 OK\nContent-Length: 2\n\nOK"
    c.debug_dev = str = ''
    c.post_content('http://photos.example.net/photos', :file => 'vacation.jpg', :size => 'original')
    assert(str.index(%q(POST /photos)))
    assert(str.index(%q(Authorization: OAuth realm="http://photos.example.net/", oauth_nonce="kllo9940pd9333jh", oauth_timestamp="1191242096", oauth_signature_method="HMAC-SHA1", oauth_token="nnch734d00sl2jdk", oauth_consumer_key="dpf43f3p2l4k3l03", oauth_signature="wPkvxykrw%2BBTdCcGqKr%2B3I%2BPsiM%3D", oauth_version="1.0")))
  end
end
