require File.expand_path('helper', File.dirname(__FILE__))
require 'webrick/https'


class TestSSL < Test::Unit::TestCase
  include Helper

  DIR = File.dirname(File.expand_path(__FILE__))

  def setup
    super
    @serverpid = @client = nil
    @verify_callback_called = false
    @verbose, $VERBOSE = $VERBOSE, nil
    setup_server
    setup_client
    @url = "https://localhost:#{serverport}/hello"
  end

  def teardown
    super
    $VERBOSE = @verbose
  end

  def path(filename)
    File.expand_path(filename, DIR)
  end

  def test_proxy_ssl
    setup_proxyserver
    escape_noproxy do
      @client.proxy = proxyurl
      @client.ssl_config.set_client_cert_file(path('client.cert'), path('client.key'))
      @client.ssl_config.add_trust_ca(path('ca.cert'))
      @client.ssl_config.add_trust_ca(path('subca.cert'))
      @client.debug_dev = str = ""
      assert_equal(200, @client.get(@url).status)
      assert(/accept/ =~ @proxyio.string, 'proxy is not used')
      assert(/Host: localhost:#{serverport}/ =~ str)
    end
  end

  def test_options
    cfg = @client.ssl_config
    assert_nil(cfg.client_cert)
    assert_nil(cfg.client_key)
    assert_nil(cfg.client_ca)
    assert_equal(OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT, cfg.verify_mode)
    assert_nil(cfg.verify_callback)
    assert_nil(cfg.timeout)
    expected_options = OpenSSL::SSL::OP_ALL | OpenSSL::SSL::OP_NO_SSLv2 | OpenSSL::SSL::OP_NO_SSLv3
    expected_options &= ~OpenSSL::SSL::OP_DONT_INSERT_EMPTY_FRAGMENTS if defined?(OpenSSL::SSL::OP_DONT_INSERT_EMPTY_FRAGMENTS)
    expected_options |= OpenSSL::SSL::OP_NO_COMPRESSION if defined?(OpenSSL::SSL::OP_NO_COMPRESSION)
    assert_equal(expected_options, cfg.options)
    assert_equal("ALL:!aNULL:!eNULL:!SSLv2", cfg.ciphers)
    assert_instance_of(OpenSSL::X509::Store, cfg.cert_store)
  end

unless defined?(HTTPClient::JRubySSLSocket)
  # JRubySSLSocket does not support sync mode.
  def test_sync
    cfg = @client.ssl_config
    cfg.set_client_cert_file(path('client.cert'), path('client.key'))
    cfg.add_trust_ca(path('ca.cert'))
    cfg.add_trust_ca(path('subca.cert'))
    assert_equal("hello", @client.get_content(@url))

    @client.socket_sync = false
    @client.reset_all
    assert_equal("hello", @client.get_content(@url))
  end
end

  def test_debug_dev
    str = @client.debug_dev = ''
    cfg = @client.ssl_config
    cfg.client_cert = path("client.cert")
    cfg.client_key = path("client.key")
    cfg.add_trust_ca(path('ca.cert'))
    cfg.add_trust_ca(path('subca.cert'))
    assert_equal("hello", @client.get_content(@url))
    assert(str.scan(/^hello$/)[0])
  end

  def test_verification
    cfg = @client.ssl_config
    cfg.verify_callback = method(:verify_callback).to_proc
    begin
      @verify_callback_called = false
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_match(/(certificate verify failed|unable to find valid certification path to requested target)/, ssle.message)
      assert(@verify_callback_called)
    end
    #
    cfg.client_cert = path("client.cert")
    cfg.client_key = path("client.key")
    @verify_callback_called = false
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_match(/(certificate verify failed|unable to find valid certification path to requested target)/, ssle.message)
      assert(@verify_callback_called)
    end
    #
    cfg.add_trust_ca(path('ca.cert'))
    @verify_callback_called = false
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_match(/(certificate verify failed|unable to find valid certification path to requested target)/, ssle.message)
      assert(@verify_callback_called)
    end
    #
    cfg.add_trust_ca(path('subca.cert'))
    @verify_callback_called = false
    assert_equal("hello", @client.get_content(@url))
    assert(@verify_callback_called)
    #
if false
  # JRubySSLSocket does not support depth.
  # Also on travis environment, verify_depth seems to not work properly.
    cfg.verify_depth = 1 # 2 required: root-sub
    @verify_callback_called = false
    begin
      @client.get(@url)
      assert(false, "verify_depth is not supported? #{OpenSSL::OPENSSL_VERSION}")
    rescue OpenSSL::SSL::SSLError => ssle
      assert_match(/(certificate verify failed|unable to find valid certification path to requested target)/, ssle.message)
      assert(@verify_callback_called)
    end
    #
    cfg.verify_depth = 2 # 2 required: root-sub
    @verify_callback_called = false
    @client.get(@url)
    assert(@verify_callback_called)
    #
end
    cfg.verify_depth = nil
    cfg.cert_store = OpenSSL::X509::Store.new
    cfg.verify_mode = OpenSSL::SSL::VERIFY_PEER
    begin
      @client.get_content(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_match(/(certificate verify failed|unable to find valid certification path to requested target)/, ssle.message)
    end
    #
    cfg.verify_mode = nil
    assert_equal("hello", @client.get_content(@url))
  end

if defined?(HTTPClient::JRubySSLSocket)
  def test_ciphers
    cfg = @client.ssl_config
    cfg.set_client_cert_file(path('client.cert'), path('client-pass.key'), 'pass4key')
    cfg.add_trust_ca(path('ca.cert'))
    cfg.add_trust_ca(path('subca.cert'))
    cfg.timeout = 123
    assert_equal("hello", @client.get_content(@url))
    #
    cfg.ciphers = []
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_match(/No appropriate protocol/, ssle.message)
    end
    #
    cfg.ciphers = %w(TLS_RSA_WITH_AES_128_CBC_SHA)
    assert_equal("hello", @client.get_content(@url))
    #
    cfg.ciphers = HTTPClient::SSLConfig::CIPHERS_DEFAULT
    assert_equal("hello", @client.get_content(@url))
  end

else

  def test_ciphers
    cfg = @client.ssl_config
    cfg.set_client_cert_file(path('client.cert'), path('client-pass.key'), 'pass4key')
    cfg.add_trust_ca(path('ca.cert'))
    cfg.add_trust_ca(path('subca.cert'))
    cfg.timeout = 123
    assert_equal("hello", @client.get_content(@url))
    #
    cfg.ciphers = "!ALL"
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_match(/no cipher match/, ssle.message)
    end
    #
    cfg.ciphers = "ALL"
    assert_equal("hello", @client.get_content(@url))
    #
    cfg.ciphers = "DEFAULT"
    assert_equal("hello", @client.get_content(@url))
  end
end

  # SSL_CERT_FILE does not work with recent jruby-openssl.
  # You should not depend on SSL_CERT_FILE on JRuby
  if !defined?(JRUBY_VERSION)
    def test_set_default_paths
      assert_raise(OpenSSL::SSL::SSLError) do
        @client.get(@url)
      end
      escape_env do
        ENV['SSL_CERT_FILE'] = File.join(DIR, 'ca-chain.pem')
        @client.ssl_config.set_default_paths
        @client.get(@url)
      end
    end
  end

  def test_no_sslv3
    teardown_server
    setup_server_with_ssl_version(:SSLv3)
    assert_raise(OpenSSL::SSL::SSLError) do
      @client.ssl_config.verify_mode = nil
      @client.get("https://localhost:#{serverport}/hello")
    end
  end

  def test_allow_tlsv1
    teardown_server
    setup_server_with_ssl_version(:TLSv1)
    assert_nothing_raised do
      @client.ssl_config.verify_mode = nil
      @client.get("https://localhost:#{serverport}/hello")
    end
  end

  def test_use_higher_TLS
    omit('TODO: it does not pass with Java 7 or old openssl ')
    teardown_server
    setup_server_with_ssl_version(:TLSv1_2)
    assert_nothing_raised do
      @client.ssl_config.verify_mode = nil
      @client.get("https://localhost:#{serverport}/hello")
      # TODO: should check JRubySSLSocket.ssl_socket.getSession.getProtocol
      # but it's not thread safe. How can I return protocol version to the caller?
    end
  end

private

  def cert(filename)
    OpenSSL::X509::Certificate.new(File.read(File.join(DIR, filename)))
  end

  def key(filename)
    OpenSSL::PKey::RSA.new(File.read(File.join(DIR, filename)))
  end

  def q(str)
    %Q["#{str}"]
  end

  def setup_server
    logger = Logger.new(STDERR)
    logger.level = Logger::Severity::FATAL	# avoid logging SSLError (ERROR level)
    @server = WEBrick::HTTPServer.new(
      :BindAddress => "localhost",
      :Logger => logger,
      :Port => 0,
      :AccessLog => [],
      :DocumentRoot => DIR,
      :SSLEnable => true,
      :SSLCACertificateFile => File.join(DIR, 'ca.cert'),
      :SSLCertificate => cert('server.cert'),
      :SSLPrivateKey => key('server.key'),
      :SSLVerifyClient => nil, #OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT|OpenSSL::SSL::VERIFY_PEER,
      :SSLClientCA => cert('ca.cert'),
      :SSLCertName => nil
    )
    @serverport = @server.config[:Port]
    [:hello].each do |sym|
      @server.mount(
        "/#{sym}",
        WEBrick::HTTPServlet::ProcHandler.new(method("do_#{sym}").to_proc)
      )
    end
    @server_thread = start_server_thread(@server)
  end

  def setup_server_with_ssl_version(ssl_version)
    logger = Logger.new(STDERR)
    logger.level = Logger::Severity::FATAL	# avoid logging SSLError (ERROR level)
    @server = WEBrick::HTTPServer.new(
      :BindAddress => "localhost",
      :Logger => logger,
      :Port => 0,
      :AccessLog => [],
      :DocumentRoot => DIR,
      :SSLEnable => true,
      :SSLCACertificateFile => File.join(DIR, 'ca.cert'),
      :SSLCertificate => cert('server.cert'),
      :SSLPrivateKey => key('server.key')
    )
    @server.ssl_context.ssl_version = ssl_version
    @serverport = @server.config[:Port]
    [:hello].each do |sym|
      @server.mount(
        "/#{sym}",
        WEBrick::HTTPServlet::ProcHandler.new(method("do_#{sym}").to_proc)
      )
    end
    @server_thread = start_server_thread(@server)
  end

  def do_hello(req, res)
    res['content-type'] = 'text/html'
    res.body = "hello"
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

  def verify_callback(ok, cert)
    @verify_callback_called = true
    p ["client", ok, cert] if $DEBUG
    ok
  end
end
