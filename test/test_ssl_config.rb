require 'test/unit'
require 'httpclient'

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

    def test_default_cert_file_is_loaded_once
      configure_context
      configure_context
      assert_equal([OpenSSL::X509::DEFAULT_CERT_FILE], @loaded_files)
    end

    def test_bundled_ca_can_be_selected_with_cacert_file
      @config.cacert_file = bundled_ca_file
      configure_context
      assert_equal([bundled_ca_file], @loaded_files)
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
