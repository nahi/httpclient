require 'test/unit'
require 'http-access2'
require 'webrick'
require 'webrick/httpproxy.rb'
require 'logger'


module HTTPAccess2


class TestClient < Test::Unit::TestCase
  Port = 17171
  ProxyPort = 17172

  def setup
    @logger = Logger.new(STDERR)
    @logger.level = Logger::Severity::ERROR
    @url = "http://localhost:#{Port}/"
    @proxyurl = "http://localhost:#{ProxyPort}/"
    @server = @proxyserver = @client = nil
    @server_thread = @proxyserver_thread = nil
    setup_server
    setup_client
  end

  def teardown
    teardown_client
    teardown_proxyserver if @proxyserver
    teardown_server
  end

  def setup_server
    @server = WEBrick::HTTPServer.new(
      :BindAddress => "0.0.0.0",
      :Logger => @logger,
      :Port => Port,
      :AccessLog => [],
      :DocumentRoot => File.dirname(File.expand_path(__FILE__))
    )
    @server_thread = start_server_thread(@server)
  end

  def setup_proxyserver
    @proxyserver = WEBrick::HTTPProxyServer.new(
      :BindAddress => "0.0.0.0",
      :Logger => @logger,
      :Port => ProxyPort,
      :AccessLog => []
    )
    @proxyserver_thread = start_server_thread(@proxyserver)
  end

  def setup_client
    @client = HTTPAccess2::Client.new
  end

  def teardown_server
    @server.shutdown
    @server_thread.kill
    @server_thread.join
  end

  def teardown_proxyserver
    @proxyserver.shutdown
    @proxyserver_thread.kill
    @proxyserver_thread.join
  end

  def teardown_client
    @client.reset(@url)
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

  def test_initialize
    #setup_proxyserver
    backup = HTTPAccess2::Client::NO_PROXY_HOSTS
    HTTPAccess2::Client.remove_const("NO_PROXY_HOSTS")
    HTTPAccess2::Client::NO_PROXY_HOSTS = []
    @client = HTTPAccess2::Client.new(@proxyurl)
    puts @client.get(@url)
    HTTPAccess2::Client::NO_PROXY_HOSTS = backup
  end

  def test_http10
    @client.protocol_version = 'HTTP/1.0'
    str = ""
    @client.debug_dev = str
    @client.get(@url)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[1])
    assert_equal("GET / HTTP/1.0", lines[2])
  end

  def test_http11
    str = ""
    @client.debug_dev = str
    @client.get(@url)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[1])
    assert_equal("GET / HTTP/1.1", lines[2])
    @client.protocol_version = 'HTTP/1.1'
    str = ""
    @client.debug_dev = str
    @client.get(@url)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[1])
    assert_equal("GET / HTTP/1.1", lines[2])
    @client.protocol_version = 'HTTP/1.0'
    str = ""
    @client.debug_dev = str
    @client.get(@url)
    lines = str.split(/(?:\r?\n)+/)
    assert_equal("= Request", lines[0])
    assert_equal("! CONNECTION ESTABLISHED", lines[1])
    assert_equal("GET / HTTP/1.0", lines[2])
  end
end


end
