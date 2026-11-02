require File.expand_path('../helper', File.dirname(__FILE__))


class JRubySocketTimeoutTest < Test::Unit::TestCase
  def test_read_timeout_is_reported_as_receive_timeout
    omit('JRuby-specific test') unless RUBY_ENGINE == 'jruby'
    socket = HTTPClient::JavaSocketWrap.allocate
    input = Object.new
    input.define_singleton_method(:read) do |_buffer|
      raise Java::JavaNet::SocketTimeoutException.new('Read timed out')
    end
    socket.instance_variable_set(:@instr, input)
    socket.instance_variable_set(:@buf, Java::byte[HTTPClient::JavaSocketWrap::BUF_SIZE].new)

    assert_raise(HTTPClient::ReceiveTimeoutError) do
      socket.send(:fill)
    end
  end
end
