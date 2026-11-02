require File.expand_path('../helper', File.dirname(__FILE__))


class JRubyMutableBuffersTest < Test::Unit::TestCase
  def setup
    omit('JRuby-specific test') unless RUBY_ENGINE == 'jruby'
  end

  def test_socket_reads_using_mutable_buffer
    input = Java::JavaIo::ByteArrayInputStream.new("hello\nworld".to_java_bytes)
    output = Java::JavaIo::ByteArrayOutputStream.new
    socket = Object.new
    socket.define_singleton_method(:getInputStream) { input }
    socket.define_singleton_method(:getOutputStream) { output }
    wrapped_socket = HTTPClient::JavaSocketWrap.new(socket)

    assert_equal("hello\n", wrapped_socket.gets("\n"))
    assert_equal('wo', wrapped_socket.read(2))
    assert_equal('rld', wrapped_socket.readpartial(3))
    assert_raise(EOFError) { wrapped_socket.readpartial(1) }
  end

  def test_trust_store_loads_multiple_pem_certificates
    loader = HTTPClient::JRubySSLSocket::TrustStoreLoader.new
    loader.add(File.expand_path('../ca-chain.pem', File.dirname(__FILE__)))

    assert_equal(2, loader.size)
    assert_equal(2, loader.trust_store.size)
  end
end
