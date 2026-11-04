require File.expand_path('test_auth', File.dirname(__FILE__))

class TestAuthFixture < Test::Unit::TestCase
  Request = Struct.new(:events) do
    def body
      events << :read_body
      'upload body'
    end
  end

  Authenticator = Struct.new(:events) do
    def authenticate(_request, _response)
      events << :authenticate
      raise WEBrick::HTTPStatus::Unauthorized
    end
  end

  def test_basic_auth_drains_body_before_challenge
    assert_body_drained_before_challenge(:basic_auth)
  end

  def test_digest_auth_drains_body_before_challenge
    assert_body_drained_before_challenge(:digest_auth)
  end

  def test_digest_sess_auth_drains_body_before_challenge
    assert_body_drained_before_challenge(:digest_sess_auth)
  end

  private

  def assert_body_drained_before_challenge(kind)
    events = []
    fixture = TestAuth.allocate
    fixture.instance_variable_set("@#{kind}", Authenticator.new(events))

    assert_raise(WEBrick::HTTPStatus::Unauthorized) do
      fixture.send("do_#{kind}", Request.new(events), Object.new)
    end
    assert_equal([:read_body, :authenticate], events)
  end
end
