require 'httpclient'

c = HTTPClient.new
conn = c.get_async("http://www.ruby-lang.org/en/")
io = conn.pop.content
while str = io.read(40)
  p str
end
