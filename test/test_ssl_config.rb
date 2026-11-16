require 'test/unit'
require 'httpclient'
require 'open3'
require 'rbconfig'

class TestSSLConfig < Test::Unit::TestCase
  # Older ruby-openssl returns generic PKey objects without DER export methods.
  CertificateWithoutKeyExport = Struct.new(:to_der) do
    def public_key
      Object.new
    end
  end

  data('X.509 v1' => false, 'X.509 v3' => true)
  def test_public_key_without_der_export(explicit_version)
    certificate = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'ca.cert')))
    public_key_der = certificate.public_key.to_der
    encoded = OpenSSL::ASN1.decode(certificate.to_der)
    unless explicit_version
      # Only the DER layout matters here; the checker does not verify signatures.
      fields = encoded.value[0].value
      fields.shift
      fields.reject! { |field| field.tag_class == :CONTEXT_SPECIFIC && field.tag == 3 }
    end
    peer = CertificateWithoutKeyExport.new(encoded.to_der)
    config = HTTPClient::SSLConfig.new(nil)
    assert_nothing_raised { config.check_peer_certificates([peer]) }

    original = HTTPClient::SSLConfig::BLOCKED_SPKI_SHA256
    HTTPClient::SSLConfig.send(:remove_const, :BLOCKED_SPKI_SHA256)
    HTTPClient::SSLConfig.const_set(:BLOCKED_SPKI_SHA256,
      original + [OpenSSL::Digest::SHA256.hexdigest(public_key_der)])
    assert_raise(OpenSSL::SSL::SSLError) { config.check_peer_certificates([peer]) }
  ensure
    if original
      HTTPClient::SSLConfig.send(:remove_const, :BLOCKED_SPKI_SHA256)
      HTTPClient::SSLConfig.const_set(:BLOCKED_SPKI_SHA256, original)
    end
  end

  def test_blocked_cross_signed_keys_without_der_export
    pem = File.read(File.join(__dir__, 'fixtures/emudhra-dv-g3b.pem'))
    certificates = pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
    assert_equal(2, certificates.size)
    certificates.each do |encoded|
      certificate = OpenSSL::X509::Certificate.new(encoded)
      peer = CertificateWithoutKeyExport.new(certificate.to_der)
      assert_raise(OpenSSL::SSL::SSLError) do
        HTTPClient::SSLConfig.new(nil).check_peer_certificates([peer])
      end
    end
  end
end

class TestCACertFile < Test::Unit::TestCase
  def setup
    @client = HTTPClient.new
    @config = @client.ssl_config
    @ca_file = File.join(__dir__, 'ca.cert')
  end

  def teardown
    @client.reset_all
  end

  # TODO(3.0.0): These tests describe the 2.x MRI default. Rewrite them with the default change.
  def test_bundled_ca_is_selected_by_default
    assert_equal(HTTPClient::SSLConfig::BUNDLED_CACERT_FILE, @config.cacert_file)
  end

  if defined?(JRUBY_VERSION)
    def test_jruby_keeps_runtime_default_trust_store
      default_items = [ENV['SSL_CERT_FILE'] || :default]
      HTTPClient::JRubySSLSocket.allocate.create_ssl_context(@config)

      assert_equal(default_items, @config.cert_store_items)
    end

    def test_load_trust_ca_adds_bundled_ca_to_jruby_defaults
      default_items = @config.cert_store_items.dup
      @config.load_trust_ca

      assert_equal(default_items + [HTTPClient::SSLConfig::BUNDLED_CACERT_FILE],
        @config.cert_store_items)
    end
  end

  def test_cacert_file_replaces_store
    @config.add_trust_ca(File.join(__dir__, 'ca-chain.pem'))
    original_store = @config.cert_store
    @config.cacert_file = @ca_file

    assert_not_same(original_store, @config.cert_store)
    assert_equal(@ca_file, @config.cacert_file)
    assert_equal([@ca_file], @config.cert_store_items) if defined?(JRUBY_VERSION)
  end

  def test_cacert_file_failure_preserves_current_configuration
    @config.cacert_file = @ca_file
    original_store = @config.cert_store

    assert_raise(OpenSSL::X509::StoreError) do
      @config.cacert_file = File.join(__dir__, 'missing-ca-file.pem')
    end

    assert_same(original_store, @config.cert_store)
    assert_equal(@ca_file, @config.cacert_file)
  end

  def test_load_trust_ca_uses_selected_file
    @config.cacert_file = @ca_file
    @config.clear_cert_store
    @config.load_trust_ca

    certificate = OpenSSL::X509::Certificate.new(File.read(@ca_file))
    @config.cert_store.time = certificate.not_before + 1
    assert(@config.cert_store.verify(certificate), @config.cert_store.error_string)
  end
end

# JRuby uses its JVM trust manager instead of SSLConfig#set_context.
unless defined?(JRUBY_VERSION)
  class TestOpenSSLTrustStore < Test::Unit::TestCase
    def setup
      @client = HTTPClient.new
      @config = @client.ssl_config
      @loaded_files = []
      loaded_files = @loaded_files
      @config.define_singleton_method(:add_trust_ca_to_store) do |_store, file|
        loaded_files << file
      end
    end

    def teardown
      @client.reset_all if @client
    end

    # TODO(3.0.0): These tests describe the 2.x MRI default. Rewrite them with the default change.
    def test_bundled_ca_is_loaded_once_by_default
      configure_context
      configure_context
      assert_equal([bundled_ca_file], @loaded_files)
    end

    def test_openssl_default_ca_can_be_selected_with_cacert_file
      @config.cacert_file = OpenSSL::X509::DEFAULT_CERT_FILE
      configure_context
      configure_context
      assert_equal([OpenSSL::X509::DEFAULT_CERT_FILE], @loaded_files)
    end

    private

    def configure_context
      context = OpenSSL::SSL::SSLContext.new
      @config.set_context(context)
      assert_same(@config.cert_store, context.cert_store)
    end

    def bundled_ca_file
      HTTPClient::SSLConfig::BUNDLED_CACERT_FILE
    end
  end
end

# Deprecation notice for the bundled CA certificates.
# TODO(3.0.0): These tests describe the 2.x MRI default. Rewrite them with the default change.
class TestBundledCACertNotice < Test::Unit::TestCase
  LIB_DIR = File.expand_path('../lib', __dir__)
  NOTICE_PATTERN = /bundled CA certificates are deprecated/

  def setup
    @client = HTTPClient.new
    @config = @client.ssl_config
    @notices = []
    notices = @notices
    # Records messages before Util#warning's once-per-process filter applies.
    # The filter itself is checked in a subprocess below.
    @config.define_singleton_method(:warning) { |message| notices << message }
  end

  def teardown
    @client.reset_all
  end

  def test_selecting_bundled_ca_file_emits_notice
    @config.cacert_file = HTTPClient::SSLConfig::BUNDLED_CACERT_FILE
    assert_equal(1, @notices.size)
  end

  def test_loading_default_trust_anchors_emits_notice
    @config.load_trust_ca
    assert_equal(1, @notices.size)
  end

  def test_notice_names_the_3_0_0_default_change_and_opt_in
    @config.load_trust_ca
    message = @notices.first
    assert_match(/deprecated/, message)
    assert_match(/HTTPClient 3\.0\.0/, message)
    assert_match(/OpenSSL::X509::DEFAULT_CERT_FILE/, message)
    assert_match(/cacert_file = OpenSSL::X509::DEFAULT_CERT_FILE/, message)
  end

  def test_custom_ca_file_does_not_emit_notice
    @config.cacert_file = File.join(__dir__, 'ca.cert')
    @config.load_trust_ca
    assert_empty(@notices)
  end

  if defined?(JRUBY_VERSION)
    # JRuby uses the JVM trust store unless the bundled file is loaded explicitly.
    def test_jruby_default_trust_store_does_not_emit_notice
      HTTPClient::JRubySSLSocket.allocate.create_ssl_context(@config)
      assert_empty(@notices)
    end
  else
    def test_default_ssl_context_emits_notice
      @config.set_context(OpenSSL::SSL::SSLContext.new)
      assert_equal(1, @notices.size)
    end

    # On JRuby, DEFAULT_CERT_FILE is a JDK keystore that OpenSSL cannot load as PEM.
    def test_openssl_default_ca_file_does_not_emit_notice
      omit('OpenSSL default CA file is missing') unless File.exist?(OpenSSL::X509::DEFAULT_CERT_FILE)
      @config.cacert_file = OpenSSL::X509::DEFAULT_CERT_FILE
      @config.load_trust_ca
      assert_empty(@notices)
    end
  end

  # Subprocess checks: process-wide once-only output and no output on creation.
  # JRuby may print its own startup warnings to stderr, so only notice lines count.

  def test_creating_client_writes_no_notice
    assert_empty(notice_lines_from('HTTPClient.new.ssl_config'))
  end

  def test_repeated_loads_write_notice_once
    lines = notice_lines_from(<<~RUBY)
      config = HTTPClient.new.ssl_config
      config.load_trust_ca
      config.cacert_file = HTTPClient::SSLConfig::BUNDLED_CACERT_FILE
      HTTPClient.new.ssl_config.load_trust_ca
    RUBY
    assert_equal(1, lines.size)
  end

  private

  def notice_lines_from(script)
    _stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I', LIB_DIR,
      '-e', "require 'httpclient'\n#{script}")
    assert(status.success?, stderr)
    stderr.lines.grep(NOTICE_PATTERN)
  end
end
