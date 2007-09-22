require 'test/unit'
require 'httpclient'


class TestSSL < Test::Unit::TestCase
  PORT = 17171
  DIR = File.dirname(File.expand_path(__FILE__))
  require 'rbconfig'
  RUBY = File.join(
    Config::CONFIG["bindir"],
    Config::CONFIG["ruby_install_name"] + Config::CONFIG["EXEEXT"]
  )

  def setup
    @url = "https://localhost:#{PORT}/hello"
    @serverpid = @client = nil
    @verify_callback_called = false
    setup_server
    setup_client
  end

  def teardown
    teardown_client
    teardown_server
  end

  def test_options
    cfg = @client.ssl_config
    assert_nil(cfg.client_cert)
    assert_nil(cfg.client_key)
    assert_nil(cfg.client_ca)
    assert_equal(OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT, cfg.verify_mode)
    assert_nil(cfg.verify_callback)
    assert_nil(cfg.timeout)
    assert_equal(OpenSSL::SSL::OP_ALL | OpenSSL::SSL::OP_NO_SSLv2, cfg.options)
    assert_equal("ALL:!ADH:!LOW:!EXP:!MD5:+SSLv2:@STRENGTH", cfg.ciphers)
    assert_instance_of(OpenSSL::X509::Store, cfg.cert_store)
  end

  def test_sync
    cfg = @client.ssl_config
    cfg.set_client_cert_file('client.cert', 'client.key')
    cfg.set_trust_ca("ca.cert")
    cfg.set_trust_ca("subca.cert")
    assert_equal("hello", @client.get_content(@url))

    @client.socket_sync = false
    @client.reset_all
    assert_equal("hello", @client.get_content(@url))
  end

  def test_debug_dev
    str = @client.debug_dev = ''
    cfg = @client.ssl_config
    cfg.client_cert = cert("client.cert")
    cfg.client_key = key("client.key")
    cfg.set_trust_ca("ca.cert")
    cfg.set_trust_ca("subca.cert")
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
      assert_equal("SSL_connect returned=1 errno=0 state=SSLv3 read server certificate B: certificate verify failed", ssle.message)
      assert(@verify_callback_called)
    end
    #
    cfg.client_cert = cert("client.cert")
    cfg.client_key = key("client.key")
    @verify_callback_called = false
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_equal("SSL_connect returned=1 errno=0 state=SSLv3 read server certificate B: certificate verify failed", ssle.message)
      assert(@verify_callback_called)
    end
    #
    cfg.set_trust_ca("ca.cert")
    @verify_callback_called = false
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_equal("SSL_connect returned=1 errno=0 state=SSLv3 read server certificate B: certificate verify failed", ssle.message)
      assert(@verify_callback_called)
    end
    #
    cfg.set_trust_ca("subca.cert")
    @verify_callback_called = false
    assert_equal("hello", @client.get_content(@url))
    assert(@verify_callback_called)
    #
    cfg.verify_depth = 1
    @verify_callback_called = false
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_equal("SSL_connect returned=1 errno=0 state=SSLv3 read server certificate B: certificate verify failed", ssle.message)
      assert(@verify_callback_called)
    end
    #
    cfg.verify_depth = nil
    cfg.cert_store = OpenSSL::X509::Store.new
    cfg.verify_mode = OpenSSL::SSL::VERIFY_PEER
    begin
      @client.get_content(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_equal("SSL_connect returned=1 errno=0 state=SSLv3 read server certificate B: certificate verify failed", ssle.message)
    end
    #
    cfg.verify_mode = nil
    assert_equal("hello", @client.get_content(@url))
  end

  def test_ciphers
    cfg = @client.ssl_config
    cfg.set_client_cert_file('client.cert', 'client.key')
    cfg.set_trust_ca("ca.cert")
    cfg.set_trust_ca("subca.cert")
    cfg.timeout = 123
    assert_equal("hello", @client.get_content(@url))
    #
    cfg.ciphers = "!ALL"
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_equal("SSL_CTX_set_cipher_list:: no cipher match", ssle.message)
    end
    #
    cfg.ciphers = "ALL"
    assert_equal("hello", @client.get_content(@url))
    #
    cfg.ciphers = "DEFAULT"
    assert_equal("hello", @client.get_content(@url))
  end

private

  def cert(filename)
    OpenSSL::X509::Certificate.new(File.open(File.join(DIR, filename)) { |f|
      f.read
    })
  end

  def key(filename)
    OpenSSL::PKey::RSA.new(File.open(File.join(DIR, filename)) { |f|
      f.read
    })
  end

  def q(str)
    %Q["#{str}"]
  end

  def setup_server
    svrcmd = "#{q(RUBY)} "
    svrcmd << "-d " if $DEBUG
    svrcmd << File.join(DIR, "sslsvr.rb")
    svrout = IO.popen(svrcmd)
    @serverpid = Integer(svrout.gets.chomp)
  end

  def setup_client
    @client = HTTPClient.new
    @client.debug_dev = STDOUT if $DEBUG
  end

  def teardown_server
    if @serverpid
      Process.kill('KILL', @serverpid)
      Process.waitpid(@serverpid)
    end
  end

  def teardown_client
    @client.reset_all if @client
  end

  def verify_callback(ok, cert)
    @verify_callback_called = true
    p ["client", ok, cert] if $DEBUG
    ok
  end
end
