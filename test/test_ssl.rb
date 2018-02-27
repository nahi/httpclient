require File.expand_path('helper', File.dirname(__FILE__))
require 'webrick/https'


class TestSSL < Test::Unit::TestCase
  include Helper

  DIR = File.dirname(File.expand_path(__FILE__))

  def setup
    super
    @serverpid = @client = nil
    @verify_callback_called = false
    setup_server
    setup_client
    @url = "https://localhost:#{serverport}/hello"
  end

  def teardown
    super
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

  def test_verification_without_httpclient
    ca_cert = ::OpenSSL::X509::Certificate.new(%w[-----BEGIN\ CERTIFICATE-----
MIIC3jCCAcYCCQCUWi3t8e122TANBgkqhkiG9w0BAQsFADAxMQ0wCwYDVQQKDARS
dWJ5MRMwEQYDVQQLDApodHRwY2xpZW50MQswCQYDVQQDDAJDQTAeFw0xODAyMjcx
MTM0NDRaFw0yODAyMjUxMTM0NDRaMDExDTALBgNVBAoMBFJ1YnkxEzARBgNVBAsM
Cmh0dHBjbGllbnQxCzAJBgNVBAMMAkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAs6FPPj8PVl1uxsMZas4VC/ibRvtyXQkfrEa7TO032Kh+ETsOQNS8
QJedhw/BMHuoVbU0/b6PZ//LJTUDN/C77/QWHKzcMoxkNye5PC2cJlSQMosaKjYG
1ERYmJ+FBiMMSpcLOCS5cYoP2fJHGtHqZPkxIPYy+IKQ7WuP3tUXkVC+ftpD6H4V
6MUnfLwagpaAAbRoFUJQoZISmH2+F5GOKX9KKiMBI94yqRRN4K/B9iqXgld45Hmg
67vX0ckRbqBhrz1CwPtaETLFB4hZT2ouBkMQYtrvpNXv80p7vcz+BwORo8b2Ns9B
4FqtpjMaS9Mf95z4Mn+NG7lanYtsHO2svwIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQBu614zHB5SS+ORYrRwl7tICKUipWHdCJfYsJOQy/FKwe7vedwd/Uclfe06GU+m
bNv0y22/oF7vrM3EfnxFe2DNIKXTndszrQSLpT6OPBe4mAOSJxnIMy6B6/PyhK6I
D7TWFSVlYX9a4OfolsoE0gQtxhyLud4rvJgXyAq9kRZ1FcNfI75cImk67rCa8jRY
TJOTidKq1Kcn6RY7d8cf581HP7y/eK887K6lBvGiQE1aFDSLe2ZLY+rxS9GSMYfK
81XhUX2QKytGYch2y95ThMwOljVTg6fKDrtKGwj9mSsnlfTFX3gikvLLtB/o7JPR
2pWBic8PX7gnANQqH/4ahv1M
-----END\ CERTIFICATE-----].join("\n"))
    cert = ::OpenSSL::X509::Certificate.new(%w[-----BEGIN\ CERTIFICATE-----
MIIC5zCCAc8CCQCz/lMJNLxQDjANBgkqhkiG9w0BAQsFADAxMQ0wCwYDVQQKDARS
dWJ5MRMwEQYDVQQLDApodHRwY2xpZW50MQswCQYDVQQDDAJDQTAeFw0xODAyMjcx
MTM1MTNaFw0yNzExMjcxMTM1MTNaMDoxDTALBgNVBAoMBFJ1YnkxEzARBgNVBAsM
Cmh0dHBjbGllbnQxFDASBgNVBAMMC0NlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAo/zP4oPyqerNyJYNTKzAGGQR8uKmP9wLnLm/yTf/
jwzVLj3rvunw54aw89V3R4LLwBBMgFlE9OrUa+2zCvZJ8ykSoltU+w9E2EdXnXAR
C/GW678MA06NPBuMNQyf+7Lv7dipdv+0hUNXFarwGiJkCms0zcmTonkOC8Bh7stZ
EykkvQs5zmYVd+G26D5un8Wzjl6OckbBDcKTS9u9H1YveRcnN7odsh+qI4PjDmKG
PXR8Gz/loNYN/I55Hqe7vkQJZ7r1PjSBp/fIcb4pNEkKS9DAcNWkoHF2j5nBNdOq
mH3WR36vKlw5S4HLzDXQDeueFbtk3QGrWY2MWrpJNapeAQIDAQABMA0GCSqGSIb3
DQEBCwUAA4IBAQB2CiGKAvHjr4kjOavWqGfPv115N4fhmBcPH4YAeJB9mHTzpoPV
BCm0ouRG5Oqj/DJhm+mckFKSorZFSgVb/G92w0uXRvBMPJb4wyIbp5ld6K3138cn
DtmeON3gbHwh3or741LdD6GIaulA9CL/qI3bbiyrJrHAZuHbpA6UqHfTKTBVi0uq
kv8qmA8FrzI2itDqdp0dq3QMNGnG40OM8NSDX+8A9wMahPh+Oe3TePSvDTahXIU1
o+dzaUEIVhUWEikQBnfeEnxzN8B/qtt3wEpliAip9Z3LuN0pVFb81Mx1wEZls2Bd
Kj83iBw7flO651USNPnkOkU3DegNtcpTaT5M
-----END\ CERTIFICATE-----].join("\n"))
    store = ::OpenSSL::X509::Store.new
    store.add_cert(ca_cert)
    assert(store.verify(cert))
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
    cfg.verify_mode = OpenSSL::SSL::VERIFY_NONE
    assert_equal("hello", @client.get_content(@url))
  end

  def test_cert_store
    cfg = @client.ssl_config
    cfg.cert_store.add_cert(cert('ca.cert'))
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_match(/(certificate verify failed|unable to find valid certification path to requested target)/, ssle.message)
    end
    #
    cfg.cert_store.add_cert(cert('subca.cert'))
    assert_equal("hello", @client.get_content(@url))
    cfg.clear_cert_store
    begin
      @client.get(@url)
      assert(false)
    rescue OpenSSL::SSL::SSLError => ssle
      assert_match(/(certificate verify failed|unable to find valid certification path to requested target)/, ssle.message)
    end
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

  def test_load_cacerts
    omit_if(RUBY_ENGINE == 'jruby', 'SSL_CERT_FILE environment does not work on JRuby')

    # disables loading default openssl paths
    stub_x509_const(:DEFAULT_CERT_FILE, '/invalid') do
      assert_raise(OpenSSL::SSL::SSLError) do
        @client.get(@url)
      end

      setup_client

      escape_env do
        ENV['SSL_CERT_FILE'] = File.join(DIR, 'ca-chain.pem')
        @client.get(@url)
      end
    end
  end

  def test_default_paths
    assert_raise(OpenSSL::SSL::SSLError) do
      @client.get(@url)
    end
    escape_env do
      ENV['SSL_CERT_FILE'] = File.join(DIR, 'ca-chain.pem')
      setup_client
      @client.get(@url)
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
    # TODO: it does not pass with Java 7 or old openssl
    teardown_server
    setup_server_with_ssl_version('TLSv1_2')
    assert_nothing_raised do
      @client.ssl_config.verify_mode = nil
      @client.get("https://localhost:#{serverport}/hello")
      # TODO: should check JRubySSLSocket.ssl_socket.getSession.getProtocol
      # but it's not thread safe. How can I return protocol version to the caller?
    end
  end

  VERIFY_TEST_CERT_LOCALHOST = OpenSSL::X509::Certificate.new(<<-EOS)
-----BEGIN CERTIFICATE-----
MIIB9jCCAV+gAwIBAgIJAIH8Gsm4PcNKMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0xNjA4MTgxMDI2MDVaFw00NDAxMDMxMDI2MDVaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
p7D8q0lcx5EZEV5+zPnQsxrbft5xyhH/MCStbH46DRATGPNSOaLRCG5r8gTKQzpD
4swGrQFYe2ienQ+7o4aEHErsXp4O/EmDKeiXWWrMqPr23r3HOBDebuynC/sCwy7N
epnX9u1VLB03eo+suj4d86OoOF+o11t9ZP+GA29Rsf8CAwEAAaNQME4wHQYDVR0O
BBYEFIxsJuPVvd5KKFcAvHGSeKSsWiUJMB8GA1UdIwQYMBaAFIxsJuPVvd5KKFcA
vHGSeKSsWiUJMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAMJaVCrrM
SM2I06Vr4BL+jtDFhZh3HmJFEDpwEFQ5Y9hduwdUGRBGCpkuea3fE2FKwWW9gLM1
w7rFMzYFtCEqm78dJWIU79MRy0wjO4LgtYfoikgBh6JKWuV5ed/+L3sLyLG0ZTtv
lrD7lzDtXgwvj007PxDoYRp3JwYzKRmTbH8=
-----END CERTIFICATE-----
  EOS

  VERIFY_TEST_CERT_FOO_DOMAIN = OpenSSL::X509::Certificate.new(<<-EOS)
-----BEGIN CERTIFICATE-----
MIIB8jCCAVugAwIBAgIJAL/od7Whx7VTMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNV
BAMMB2Zvby5jb20wHhcNMTYwODE4MTAyMzUyWhcNNDQwMTAzMTAyMzUyWjASMRAw
DgYDVQQDDAdmb28uY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnsPyr
SVzHkRkRXn7M+dCzGtt+3nHKEf8wJK1sfjoNEBMY81I5otEIbmvyBMpDOkPizAat
AVh7aJ6dD7ujhoQcSuxeng78SYMp6JdZasyo+vbevcc4EN5u7KcL+wLDLs16mdf2
7VUsHTd6j6y6Ph3zo6g4X6jXW31k/4YDb1Gx/wIDAQABo1AwTjAdBgNVHQ4EFgQU
jGwm49W93kooVwC8cZJ4pKxaJQkwHwYDVR0jBBgwFoAUjGwm49W93kooVwC8cZJ4
pKxaJQkwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQCVKTvfxx+yezuR
5WpVKw1E9qabKOYFB5TqdHMHreRubMJTaoZC+YzhcCwtyLlAA9+axKINAiMM8T+z
jjfOHQSa2GS2TaaVDJWmXIgsAlEbjd2BEiQF0LZYGJRG9pyq0WbTV+CyFdrghjcO
xX/t7OG7NfOG9dhv3J+5SX10S5V5Dg==
-----END CERTIFICATE-----
  EOS

  VERIFY_TEST_CERT_ALT_NAME = OpenSSL::X509::Certificate.new(<<-EOS)
-----BEGIN CERTIFICATE-----
MIICDDCCAXWgAwIBAgIJAOxXY4nOwxhGMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0xNjA4MTgxMDM0NTJaFw00NDAxMDMxMDM0NTJaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
p7D8q0lcx5EZEV5+zPnQsxrbft5xyhH/MCStbH46DRATGPNSOaLRCG5r8gTKQzpD
4swGrQFYe2ienQ+7o4aEHErsXp4O/EmDKeiXWWrMqPr23r3HOBDebuynC/sCwy7N
epnX9u1VLB03eo+suj4d86OoOF+o11t9ZP+GA29Rsf8CAwEAAaNmMGQwFAYDVR0R
BA0wC4IJKi5mb28uY29tMB0GA1UdDgQWBBSMbCbj1b3eSihXALxxknikrFolCTAf
BgNVHSMEGDAWgBSMbCbj1b3eSihXALxxknikrFolCTAMBgNVHRMEBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4GBADJlKNFuOnsDIhHGW72HuQw4naN6lM3eZE9JJ+UF/XIF
ghGtgqw+00Yy5wMFc1K2Wm4p5NymmDfC/P1FOe34bpxt9/IWm6mEoIWoodC3N4Cm
PtnSS1/CRWzVIPGMglTGGDcUc70tfeAWgyTxgcNQd4vTFtnN0f0RDdaXa8kfKMTw
-----END CERTIFICATE-----
  EOS

  VERIFY_TEST_PKEY = OpenSSL::PKey::RSA.new(<<-EOS)
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCnsPyrSVzHkRkRXn7M+dCzGtt+3nHKEf8wJK1sfjoNEBMY81I5
otEIbmvyBMpDOkPizAatAVh7aJ6dD7ujhoQcSuxeng78SYMp6JdZasyo+vbevcc4
EN5u7KcL+wLDLs16mdf27VUsHTd6j6y6Ph3zo6g4X6jXW31k/4YDb1Gx/wIDAQAB
AoGAe0RHx+WKtQx8/96VmTl951qzxMPho2etTYd4kAsNwzJwx2N9qu57eBYrdWF+
CQMYievucFhP4Y+bINtC1Eb6btz9TCUwjCfeIxfGRoFf3cxVmxlsRJJmN1kSZlu1
yYlcMVuP4noeFIMQBRrt5pyLCx2Z9A01NCQT4Y6VoREBIeECQQDWeNhsL6xkrmdB
M9+zl+SqHdNKhgKwMdp74+UNnAV9I8GB7bGlOWhc83aqMLgS+JBDFXcmNF/KawTR
zcnkod5xAkEAyClFgr3lZQSnwUwoA/AOcyW0+H63taaaXS/g8n3H8ENK6kL4ldUx
IgCk2ekbQ5Y3S2WScIGXNxMOza9MlsOvbwJAPUtoPvMZB+U4KVBT/JXKijvf6QqH
tidpU8L78XnHr84KPcHa5WeUxgvmvBkUYoebYzC9TrPlNIqFZBi2PJtuYQJBAMda
E5j7eJT75fhm2RPS6xFT5MH5sw6AOA3HucrJ63AoFVzsBpl0E9NBwO4ndLgDzF6T
cx4Kc4iuunewuB8QFpECQQCfvsHCjIJ/X4kiqeBzxDq2GR/oDgQkOzY+4H9U7Lwl
e61RBaxk5OHOA0bLtvJblV6NL72ZEZhX60wAWbrOPhpT
-----END RSA PRIVATE KEY-----
  EOS

  def test_post_connection_check
    teardown_server
    setup_server_with_server_cert(nil, VERIFY_TEST_CERT_LOCALHOST, VERIFY_TEST_PKEY)
    file = Tempfile.new('cert')
    File.write(file.path, VERIFY_TEST_CERT_LOCALHOST.to_pem)
    @client.ssl_config.add_trust_ca(file.path)
    assert_nothing_raised do
      @client.get("https://localhost:#{serverport}/hello")
    end
    @client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
    assert_nothing_raised do
      @client.get("https://localhost:#{serverport}/hello")
    end
    @client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_PEER

    teardown_server
    setup_server_with_server_cert(nil, VERIFY_TEST_CERT_FOO_DOMAIN, VERIFY_TEST_PKEY)
    File.write(file.path, VERIFY_TEST_CERT_FOO_DOMAIN.to_pem)
    @client.ssl_config.add_trust_ca(file.path)
    assert_raises(OpenSSL::SSL::SSLError) do
      @client.get("https://localhost:#{serverport}/hello")
    end
    @client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
    assert_nothing_raised do
      @client.get("https://localhost:#{serverport}/hello")
    end
    @client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_PEER

    teardown_server
    setup_server_with_server_cert(nil, VERIFY_TEST_CERT_ALT_NAME, VERIFY_TEST_PKEY)
    File.write(file.path, VERIFY_TEST_CERT_ALT_NAME.to_pem)
    @client.ssl_config.add_trust_ca(file.path)
    assert_raises(OpenSSL::SSL::SSLError) do
      @client.get("https://localhost:#{serverport}/hello")
    end
    @client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
    assert_nothing_raised do
      @client.get("https://localhost:#{serverport}/hello")
    end
    @client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_PEER
  end

  def test_x509_store_add_cert_prepend
    store = OpenSSL::X509::Store.new
    assert_equal(store, store.add_cert(OpenSSL::X509::Certificate.new(VERIFY_TEST_CERT_LOCALHOST)))
  end

  def test_tcp_keepalive
    @client.tcp_keepalive = true
    @client.ssl_config.add_trust_ca(path('ca-chain.pem'))
    @client.get_content(@url)

    # expecting HTTP keepalive caches the socket
    session = @client.instance_variable_get(:@session_manager).send(:get_cached_session, HTTPClient::Site.new(URI.parse(@url)))
    socket = session.instance_variable_get(:@socket).instance_variable_get(:@socket)

    assert_true(session.tcp_keepalive)
    if RUBY_ENGINE == 'jruby'
      assert_true(socket.getKeepAlive())
    else
      assert_equal(Socket::SO_KEEPALIVE, socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE).optname)
    end
  end

  def test_timeout
    url = "https://localhost:#{serverport}/"
    @client.ssl_config.add_trust_ca(path('ca-chain.pem'))
    assert_equal('sleep', @client.get_content(url + 'sleep?sec=2'))
    @client.receive_timeout = 1
    @client.reset_all
    assert_equal('sleep', @client.get_content(url + 'sleep?sec=0'))

    start = Time.now
    assert_raise(HTTPClient::ReceiveTimeoutError) do
      @client.get_content(url + 'sleep?sec=5')
    end
    if Time.now - start > 3
      # before #342 it detected timeout when IO was freed
      fail 'timeout does not work'
    end

    @client.receive_timeout = 3
    @client.reset_all
    assert_equal('sleep', @client.get_content(url + 'sleep?sec=2'))
  end

private

  def stub_x509_const(name, value)
    OpenSSL::X509.module_eval do
      begin
        original = remove_const(name)
        const_set(name, value)

        yield
      ensure
        remove_const(name)
        const_set(name, original)
      end
    end
  end

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
    [:hello, :sleep].each do |sym|
      @server.mount(
        "/#{sym}",
        WEBrick::HTTPServlet::ProcHandler.new(method("do_#{sym}").to_proc)
      )
    end
    @server_thread = start_server_thread(@server)
  end

  def setup_server_with_ssl_version(ssl_version)
    # JRubyOpenSSL does not support "TLSv1_2" as an known version, and some JCE provides TLS v1.2 as "TLSv1.2" not "TLSv1_2"
    if RUBY_ENGINE == 'jruby' && ['TLSv1_1', 'TLSv1_2'].include?(ssl_version)
      ssl_version = ssl_version.tr('_', '.')
    end
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

  def setup_server_with_server_cert(ca_cert, server_cert, server_key)
    logger = Logger.new(STDERR)
    logger.level = Logger::Severity::FATAL	# avoid logging SSLError (ERROR level)
    @server = WEBrick::HTTPServer.new(
      :BindAddress => "localhost",
      :Logger => logger,
      :Port => 0,
      :AccessLog => [],
      :DocumentRoot => DIR,
      :SSLEnable => true,
      :SSLCACertificateFile => ca_cert,
      :SSLCertificate => server_cert,
      :SSLPrivateKey => server_key,
      :SSLVerifyClient => nil,
      :SSLClientCA => nil,
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

  def do_hello(req, res)
    res['content-type'] = 'text/html'
    res.body = "hello"
  end

  def do_sleep(req, res)
    sec = req.query['sec'].to_i
    sleep sec
    res['content-type'] = 'text/html'
    res.body = "sleep"
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
