module HtHelpers
  def params(str)
    HTTP::Message.parse(str).inject({}) { |r, (k, v)| r[k] = v.first; r }
  end
end

RSpec.configure do |config|
  config.extend HtHelpers
  config.include HTTPClient::Util
end
