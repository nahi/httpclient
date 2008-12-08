require 'httpclient'

proxy = 'http://localhost:3128/'

c = HTTPClient.new(proxy)
c.debug_dev = STDOUT

# for Proxy authentication: supports Basic, Negotiate and NTLM.
c.set_proxy_auth("admin", "admin")

# for WWW authentication: supports Basic, Digest and Negotiate.
c.set_auth("http://jp.ctor.org/c/", "user", "user")
p c.get("http://dev.ctor.org/soap4r/login")
