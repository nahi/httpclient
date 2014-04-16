module HtHelpers
  def params(str)
    HTTP::Message.parse(str).inject({}) { |r, (k, v)| r[k] = v.first; r }
  end
  def check_query_get(query)
    WEBrick::HTTPUtils.parse_query(@client.get(@srv.u("servlet"), query).header["x-query"][0])
  end
  def check_query_post(query)
    WEBrick::HTTPUtils.parse_query(@client.post(@srv.u("servlet"), query).header["x-query"][0])
  end

  def without_noproxy
    backup = HTTPClient::NO_PROXY_HOSTS.dup
    HTTPClient::NO_PROXY_HOSTS.clear
    yield
  ensure
    HTTPClient::NO_PROXY_HOSTS.replace(backup)
  end

  def silent
    begin
      back, $VERBOSE = $VERBOSE, nil
      yield
    ensure
      $VERBOSE = back
    end
  end
end

RSpec.configure do |config|
  config.include HtHelpers
  config.include HTTPClient::Util
end

