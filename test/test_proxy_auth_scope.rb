require File.expand_path('helper', File.dirname(__FILE__))
require 'webrick/https'

class TestProxyAuthScope < Test::Unit::TestCase
  include Helper

  PROXY_CREDENTIAL = 'Basic ' + ['proxy-user:proxy-secret'].pack('m0')
  ORIGIN_CREDENTIAL = 'Basic ' + ['origin-user:origin-secret'].pack('m0')

  class HeaderFilter
    attr_reader :requests, :responses

    def initialize
      @requests = @responses = 0
    end

    def filter_request(req)
      @requests += 1
      req.header.add('Proxy-Authorization', 'custom filter value')
      req.header.add('X-Scope-Filter', 'present')
    end

    def filter_response(_req, _res)
      @responses += 1
      nil
    end
  end

  def setup
    super
    setup_client
    @client.proxy = nil
    @client.no_proxy = nil
    @client.set_proxy_auth('proxy-user', 'proxy-secret')
    @origin_requests = Queue.new
    @proxy_requests = Queue.new
  end

  data('Basic' => 'Basic', 'Digest' => 'Digest')
  def test_redirect_to_no_proxy(scheme)
    start_origin
    start_proxy(scheme)
    assert_equal('OK', @client.get_content('http://upstream.invalid/redirect'))
    assert_proxy_authenticated(scheme)
    assert_equal([[]], drain(@origin_requests).map { |request| request[:proxy_auth] })
  end

  data('sync Basic listed' => [:sync, 'Basic', false],
       'async Basic listed' => [:async, 'Basic', false],
       'sync Digest listed' => [:sync, 'Digest', false],
       'async Digest listed' => [:async, 'Digest', false],
       'sync Basic localhost' => [:sync, 'Basic', true],
       'async Basic localhost' => [:async, 'Basic', true])
  def test_direct_request_after_proxy_authentication(settings)
    mode, scheme, implicit_localhost = settings
    start_origin
    start_proxy(scheme)
    assert_equal('OK', @client.get_content('http://upstream.invalid/warm'))
    assert_proxy_authenticated(scheme)
    url = @origin_url
    if implicit_localhost
      @client.no_proxy = nil
      url = "http://localhost:#{serverport}/"
    end
    assert_equal(200, request(mode, url).status)
    assert_equal([[]], drain(@origin_requests).map { |record| record[:proxy_auth] })
    assert_equal('OK', @client.get_content('http://upstream.invalid/again'))
    assert_match(/\A#{scheme} /, drain(@proxy_requests).last[:proxy_auth].first)
  end

  data('sync' => :sync, 'async' => :async)
  def test_forced_basic_auth_preserves_origin_auth(mode)
    start_origin
    start_proxy
    @client.force_basic_auth = true
    @client.set_auth(@origin_url, 'origin-user', 'origin-secret')
    assert_equal(200, request(mode, 'http://upstream.invalid/').status)
    assert_equal([PROXY_CREDENTIAL], drain(@proxy_requests).first[:proxy_auth])
    assert_equal(200, request(mode, @origin_url).status)
    record = @origin_requests.pop
    assert_equal([], record[:proxy_auth])
    assert_equal([ORIGIN_CREDENTIAL], record[:origin_auth])
  end

  data('sync request with proxy' => [:sync, false, true],
       'async request with proxy' => [:async, false, true],
       'sync defaults with proxy' => [:sync, true, true],
       'async defaults with proxy' => [:async, true, true],
       'sync request without proxy' => [:sync, false, false],
       'async request without proxy' => [:async, false, false],
       'sync defaults without proxy' => [:sync, true, false],
       'async defaults without proxy' => [:async, true, false])
  def test_explicit_headers_on_direct_requests(settings)
    mode, defaults, configured_proxy = settings
    start_origin
    start_proxy if configured_proxy
    headers = { 'pRoXy-AuThOrIzAtIoN' => ['first', 'second'],
                'Proxy-Authorization' => 'third' }
    @client.default_header.update(headers) if defaults
    assert_equal(200, request(mode, @origin_url, defaults ? {} : headers).status)
    assert_equal([], @origin_requests.pop[:proxy_auth])
    assert_equal(['first', 'second'], headers['pRoXy-AuThOrIzAtIoN'])
    assert_equal('third', headers['Proxy-Authorization'])
  end

  data('sync' => :sync, 'async' => :async)
  def test_explicit_header_on_forwarding_request(mode)
    start_origin
    start_proxy
    assert_equal(200, request(mode, 'http://upstream.invalid/', 'Proxy-Authorization' => PROXY_CREDENTIAL).status)
    records = drain(@proxy_requests)
    assert_equal(1, records.size)
    assert_equal([PROXY_CREDENTIAL], records.first[:proxy_auth])
    assert(@origin_requests.empty?)
  end

  data('sync' => :sync, 'async' => :async)
  def test_custom_filters_still_run_on_direct_requests(mode)
    start_origin
    start_proxy
    filter = HeaderFilter.new
    @client.request_filter << filter
    assert_equal(200, request(mode, @origin_url).status)
    record = @origin_requests.pop
    assert_equal([], record[:proxy_auth])
    assert_equal('present', record[:custom_filter])
    assert_equal(1, filter.requests)
    assert_equal(1, filter.responses)
  end

  data('sync' => :sync, 'async' => :async)
  def test_direct_response_cannot_challenge_proxy(mode)
    start_origin
    start_proxy
    assert_equal(407, request(mode, @origin_url + 'proxy_challenge').status)
    assert_equal(1, drain(@origin_requests).size, 'origin 407 must not cause proxy authentication retries')
    assert_nil(@client.proxy_auth.basic_auth.get(nil))
    assert_equal('OK', @client.get_content('http://upstream.invalid/warm'))
    assert_proxy_authenticated('Basic')
  end

  data('sync' => :sync, 'async' => :async)
  def test_loopback_response_does_not_bypass_direct_route_protection(mode)
    @client.proxy = 'http://proxy.invalid:8080'
    @client.no_proxy = 'direct.invalid'
    @client.force_basic_auth = true
    @client.test_loopback_http_response << "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    @client.debug_dev = log = ''.dup
    assert_equal(200, request(mode, 'http://direct.invalid/').status)
    assert_not_match(/Proxy-Authorization:/i, log)
  end

  data('sync challenged' => [:sync, false], 'async challenged' => [:async, false],
       'sync forced' => [:sync, true], 'async forced' => [:async, true])
  def test_https_credentials_only_reach_connect(settings)
    mode, force = settings
    start_origin(true)
    start_proxy('Basic', true)
    @client.force_basic_auth = force
    @client.protocol_version = '1.1'
    @client.set_auth(@origin_url, 'origin-user', 'origin-secret')
    @client.www_auth.basic_auth.force_auth = true
    escape_noproxy do
      assert_equal(200, request(:sync, @origin_url).status)
      assert_equal(200, request(mode, @origin_url, 'pRoXy-AuThOrIzAtIoN' => ['first', 'second']).status)
    end
    proxy_requests = drain(@proxy_requests)
    assert_equal(force ? 1 : 2, proxy_requests.size, 'the authenticated tunnel should be reused')
    assert(proxy_requests.all? { |record| record[:method] == 'CONNECT' })
    assert_equal([PROXY_CREDENTIAL], proxy_requests.last[:proxy_auth])
    records = drain(@origin_requests)
    assert_equal([[], []], records.map { |record| record[:proxy_auth] })
    assert_equal([[ORIGIN_CREDENTIAL], [ORIGIN_CREDENTIAL]], records.map { |record| record[:origin_auth] })
  end

  data('sync' => :sync, 'async' => :async)
  def test_https_origin_response_cannot_challenge_proxy(mode)
    start_origin(true)
    start_proxy('Basic', true)
    @client.protocol_version = '1.1'
    escape_noproxy do
      assert_equal(200, request(:sync, @origin_url).status)
      @client.proxy_auth.reset_challenge
      assert_equal(407, request(mode, @origin_url + 'proxy_challenge').status)
    end
    assert_equal(2, drain(@origin_requests).size)
    assert_nil(@client.proxy_auth.basic_auth.get(nil))
    assert_equal(2, drain(@proxy_requests).size, 'origin 407 must not reopen the CONNECT tunnel')
  end

  def test_parallel_direct_and_proxied_requests
    start_origin
    start_proxy
    assert_equal('OK', @client.get_content('http://upstream.invalid/warm'))
    assert_proxy_authenticated('Basic')
    threads = 10.times.map do |index|
      Thread.new do
        url = index.even? ? @origin_url : 'http://upstream.invalid/again'
        @client.get(url).status
      end
    end
    assert_equal([200] * 10, threads.map(&:value))
    assert_equal([[]] * 5, drain(@origin_requests).map { |record| record[:proxy_auth] })
    assert_equal([[PROXY_CREDENTIAL]] * 5, drain(@proxy_requests).map { |record| record[:proxy_auth] })
  ensure
    threads.each { |thread| thread.join } if threads
  end

  private

  def start_origin(ssl = false)
    options = { :BindAddress => '127.0.0.1', :Port => 0, :AccessLog => [], :Logger => @logger }
    if ssl
      options.update(:SSLEnable => true,
        :SSLCertificate => OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'server.cert'))),
        :SSLPrivateKey => OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, 'server.key'))))
      @client.ssl_config.add_trust_ca(File.join(__dir__, 'ca-chain.pem'))
    end
    @server = WEBrick::HTTPServer.new(options)
    @serverport = @server.config[:Port]
    @server.mount_proc('/') do |req, res|
      @origin_requests << record(req)
      if req.path == '/proxy_challenge'
        res.status = 407
        res['Proxy-Authenticate'] = 'Basic realm="untrusted origin"'
      end
      res.body = 'OK'
    end
    @server_thread = start_server_thread(@server)
    @origin_url = ssl ? "https://localhost:#{serverport}/" : "http://127.0.0.1:#{serverport}/"
  end

  def start_proxy(scheme = 'Basic', tunnel = false)
    @proxy_scheme = scheme
    options = { :BindAddress => '127.0.0.1', :Port => 0, :AccessLog => [], :Logger => @proxylogger }
    if tunnel
      options[:ProxyAuthProc] = method(:authenticate_proxy).to_proc
      @proxyserver = WEBrick::HTTPProxyServer.new(options)
    else
      # A fake forwarding proxy: never resolves or connects to upstream.invalid.
      @proxyserver = WEBrick::HTTPServer.new(options)
      @proxyserver.mount_proc('/') do |req, res|
        authenticate_proxy(req, res)
        if req.path == '/redirect'
          res.status = 302
          res['Location'] = @origin_url
        end
        res.body = 'OK'
      end
    end
    @proxyport = @proxyserver.config[:Port]
    @proxyserver_thread = start_server_thread(@proxyserver)
    @client.proxy = "http://127.0.0.1:#{proxyport}/"
    @client.no_proxy = "127.0.0.1:#{serverport}"
  end

  def authenticate_proxy(req, res)
    @proxy_requests << record(req)
    unless req['proxy-authorization']
      res['Proxy-Authenticate'] = @proxy_scheme == 'Basic' ?
        'Basic realm="proxy"' : 'Digest realm="proxy", nonce="test-nonce", qop="auth"'
      raise WEBrick::HTTPStatus::ProxyAuthenticationRequired
    end
  end

  def record(req)
    { :proxy_auth => req.header['proxy-authorization'].dup,
      :origin_auth => req.header['authorization'].dup, :method => req.request_method,
      :custom_filter => req['x-scope-filter'] }
  end

  def drain(queue)
    Array.new(queue.size) { queue.pop }
  end

  def assert_proxy_authenticated(scheme)
    records = drain(@proxy_requests)
    assert_equal(2, records.size)
    assert_equal([], records.first[:proxy_auth])
    assert_match(/\A#{scheme} /, records.last[:proxy_auth].first)
    assert_equal([PROXY_CREDENTIAL], records.last[:proxy_auth]) if scheme == 'Basic'
  end

  def request(mode, url, headers = {})
    return @client.get(url, :header => headers) if mode == :sync
    connection = @client.get_async(url, :header => headers)
    response = connection.pop
    response.body.read
    connection.join
    response
  end
end
