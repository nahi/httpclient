require 'test/unit'
require 'http-access2'
require 'webrick/https'
require 'logger'
require 'stringio'
require 'cgi'
require 'webrick/httputils'
require 'drb/drb'


module HTTPAccess2


class TestSSL < Test::Unit::TestCase
  PORT = 17171
  DIR = File.dirname(File.expand_path(__FILE__))
  require 'rbconfig'
  RUBY = File.join(
    Config::CONFIG["bindir"],
    Config::CONFIG["ruby_install_name"] + Config::CONFIG["EXEEXT"]
  )

  def setup
    @logger = Logger.new(STDERR)
    @logger.level = Logger::Severity::ERROR
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

  def test_certificate
    @client.ssl_config.verify_callback = method(:verify_callback).to_proc
    begin
      @verify_callback_called = false
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_equal("certificate verify failed", ssle.message)
      assert(@verify_callback_called)
    end
    @client.ssl_config.client_cert = cert("client.cert")
    @client.ssl_config.client_key = key("client.key")
    begin
      @verify_callback_called = false
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_equal("certificate verify failed", ssle.message)
      assert(@verify_callback_called)
    end
    @verify_callback_called = false
    @client.ssl_config.set_trust_ca("ca.cert")
    assert_equal("hello", @client.get_content(@url))
    assert(@verify_callback_called)
    #
    @client.ssl_config.verify_depth = 1
    @verify_callback_called = false
    assert_equal("hello", @client.get_content(@url))
    assert(!@verify_callback_called)
    #
    @client.ssl_config.verify_depth = 0
    @verify_callback_called = false
    assert_equal("hello", @client.get_content(@url))
    assert(!@verify_callback_called)
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
    @client = HTTPAccess2::Client.new
    @client.debug_dev = STDOUT if $DEBUG
  end

  def teardown_server
    Process.kill('INT', @serverpid)
  end

  def teardown_client
    @client.reset_all
  end

  def verify_callback(ok, cert)
    @verify_callback_called = true
    p ["client", ok, cert] if $DEBUG
    ok
  end
end


end
