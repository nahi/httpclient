http-access2 - HTTP accessing library.
Copyright (C) 2000, 2001, 2002, 2003  NAKAMURA, Hiroshi.

This module is copyrighted free software by NAKAMURA, Hiroshi.
You can redistribute it and/or modify it under the same term as Ruby.

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

  See sample/howto.rb how to use APIs.  For more detail, see RDoc comment in
  lib/http-access2.rb or http://rrr.jin.gr.jp/doc/http-access2/ .


- Author

  Name: NAKAMURA, Hiroshi
  E-mail: nakahiro@sarion.co.jp


- History

  September 10, 2003 - version 2.0
    CamelCase to non_camel_case.
    SSL support (requires Ruby/OpenSSL).
    Cookies support.  lib/http-access2/cookie.rb is redistributed file which is
      originally included in Webagent by TAKAHASHI `Maki' Masayoshi.  You can
      download the entire package from http://www.rubycolor.org/arc/.

  January 11, 2003 - version J
    ruby/1.8 support.
