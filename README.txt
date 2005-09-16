http-access2 - HTTP accessing library.
Copyright (C) 2000-2005  NAKAMURA, Hiroshi  <nakahiro@sarion.co.jp>.

This program is copyrighted free software by NAKAMURA, Hiroshi.  You can
redistribute it and/or modify it under the same terms of Ruby's license;
either the dual license version in 2003, or any later version.

http-access2.rb is based on http-access.rb in http-access/0.0.4.  Some part
of code in http-access.rb was recycled in http-access2.rb.  Those part is
copyrighted by Maehashi-san who made and distributed http-access/0.0.4. Many
thanks to Maehashi-san.


- Introduction

  http-access2 gives something like the functionality of libwww-perl (LWP) in
  Ruby.

  Features;
  * methods like GET/HEAD/POST via HTTP/1.1.
  * asynchronous HTTP request
  * HTTPS(SSL)
  * by contrast with net/http in standard distribution;
    * you don't have to care HTTP/1.1 persistent connection (http-access2 cares
      instead of you). 
    * MT-safe
    * streaming POST
    * Cookies

  Not supported now;
  * Cache
  * Rather advanced HTTP/1.1 usage such as Range, deflate, etc. (of cource you
    can set it in header by yourself)


- Install

  $ ruby install.rb
  It will install lib/http-access2.rb and lib/http-access2/http.rb to your
  site_ruby directory such as /usr/local/lib/ruby/site_ruby/1.8/.


- Uninstall

  Delete installed files from your site_ruby directory.


- Usage

  See sample/howto.rb how to use APIs.


- Author

  Name: NAKAMURA, Hiroshi
  E-mail: nakahiro@sarion.co.jp


- Changes

  September 16, 2005 - version 2.0.6

    * HTTP
      * allows redirects from a "POST" request.  imported a patch from sveit.
        Thanks! (#7)
      * add 'content-type: application/application/x-www-form-urlencoded' when
        a request contains message-body. (#11)
      * HTTP/0.9 support.  (#15)
      * allows submitting multipart forms.  imported a patch from sveit.
        Thanks! (#7)

    * HTTP-Cookies
      * avoid NameError when a cookie value is nil. (#10)
      * added netscape_rule property to CookieManager (false by default).  You
        can turn on the domain attribute test of Netscape rule with the
        property.  cf. http://wp.netscape.com/newsref/std/cookie_spec.html
      * added HTTPClient#cookie_manager property for accessing its properties.
        (#13)
      * added save_all_cookies method to save unused and discarded cookies as
        well.  The patch is from Christian Lademann.  Thanks!  (#21)
      * allow to set cookie_manager.  raise an error when set_cookie_store
        called and cookie_store has already been set. (#20)

    * SSL
      * allows SSL connection debugging when debug_dev != nil. (#14)
      * skip post_connection_check when
        verify_mode == OpenSSL::SSL::VERIFY_NONE.  Thanks to kdraper. (#12)
      * post_connection_check: support a certificate with a wildcard in the
        hostname. (#18)
      * avoid NameError when no peer_cert and VERIFY_FAIL_IF_NO_PEER_CERT
        given.  Thanks to Christian Lademann.

    * Connection
      * insert a connecting host and port to an exception message when
        connecting failed. (#5)
      * added socket_sync property to HTTPClient(HTTPAccess2::Client) that
        controls socket's sync property.  the default value is true.  CAUTION:
        if your ruby is older than 2005-09-06 and you want to use SSL
        connection, do not set socket_sync = false to avoid a blocking bug of
        openssl/buffering.rb.

  December 24, 2004 - version 2.0.5
    This is a minor bug fix release.
    - Connect/Send/Receive timeout cannot be configured. fixed.
    - IPSocket#addr caused SocketError? on Mac OS X 10.3.6 + ruby-1.8.1 GA.
      fixed.
    - There is a server which does not like 'foo.bar.com:80' style Host header.
      The server for http://rubyforge.org/export/rss_sfnews.php seems to
      dislike HTTP/1.1 Host header "Host: rubyforge.net:80".  It returns
      HTTP 302: Found and redirects to the page again, causes
      HTTPAccess2::Client to raise "retry count exceeded".  Keat found that the
      server likes "Host: rubyforge.net" (not with port number).

  February 11, 2004 - version 2.0.4
    - add Client#redirect_uri_callback interface.
    - refactorings and bug fixes found during negative test.
    - add SSL test.

  December 16, 2003 - version 2.0.3
    - no_proxy was broken in 2.0.2.
    - do not dump 'Host' header under protocol_version == 'HTTP/1.0'

  December ?, 2003 - version 2.0.2
    - do not trust HTTP_PROXY environment variable. set proxy server manually.
      http://ftp.ics.uci.edu/pub/websoft/libwww-perl/archive/2001h1/0072.html
      http://ftp.ics.uci.edu/pub/websoft/libwww-perl/archive/2001h1/0241.html
      http://curl.haxx.se/mail/archive-2001-12/0034.html
    - follow ossl2 change.

  October 4, 2003 - version 2.0.1
    Query was not escaped when query was given as an Array or a Hash.  Fixed.
    Do not use http_proxy defined by ENV['http_proxy'] or ENV['HTTP_PROXY'] if
      the destination host is 'localhost'.
    Hosts which matches ENV['no_proxy'] or ENV['NO_PROXY'] won't be proxyed.
      [,:] separated. ("ruby-lang.org:rubyist.net")
      No regexp. (give "ruby-lang.org", not "*.ruby-lang.org")
      If you want specify hot by IP address, give full address.
	("192.168.1.1, 192.168.1.2")

  September 10, 2003 - version 2.0
    CamelCase to non_camel_case.
    SSL support (requires Ruby/OpenSSL).
    Cookies support.  lib/http-access2/cookie.rb is redistributed file which is
      originally included in Webagent by TAKAHASHI `Maki' Masayoshi.  You can
      download the entire package from http://www.rubycolor.org/arc/.

  January 11, 2003 - version J
    ruby/1.8 support.
