require 'http-access2'

c = HTTPAccess2::Client.new
conn = c.get_async("http://www.ruby-lang.org/en/")
io = conn.pop.content
while str = io.read(40)
  p str
end
