## Changes

### Changes in 2.8.2

Aug 15, 2016 - version 2.8.2

 * Bug

   * 2.8.1 introduced JRuby + SSL connection problem; in some cases it cannot
     connect to trusted TLS server. 2.8.1 failed to load multiple CA
     certificates in a file. #327.

Aug 16, 2016 - version 2.8.2.1

 * Bug

   * 2.8.1 introduced another bug that causes NPE from JRuby when JRuby
     program loads httpclient and uses OpenSSL::X509::Store outside of
     httpclient. 2.8.3 fixed this problem. #325

Aug 28, 2016 - version 2.8.2.3

 * Bug

   * 2.8.2 fixed VERIFY_NONE at JRuby but the fix was not enough.

### Changes in 2.8.1

Aug 8, 2016 - version 2.8.1

 * Changes

   * Use TLSv1.2 always on JRuby #320

   * Do not reset keep-alive connection by configuration change #315

   * Add strict_response_size_check option #316
     false by default, meaning it behavies like browsers by default.

   * Add MIME type for XML #308

 * Bug

   * Direct access to SSLConfig#cert_store in JRuby was broken from 2.7 #276 #317

   * OpenSSL::SSL::VERIFY_NONE does not work in JRuby #319

   * Allow receiving response body in block when follow_redirects => true. #304

   * Fix blocking issue with request_async when Encoding.default_internal is set. #307

   * Apply timeouts for chunked transfer encoding #309

### Changes in 2.8.0

Apr 24, 2016 - version 2.8.0

 * Changes

   * Force using RSA 2048bit CA cert set

     Use RSA 2048bit CA cert set every time if it runs with OpenSSL (== except
     JRuby.)

     Old openssl (<1.0.1p or <1.0.2d) cannot handle this CA set and causes
     SSL connection failure against some SSL servers including AWS S3 API.
     For such case you can manually specify RSA 1024bit CA cert set as a
     workaround.

     ```
     c = HTTPClient.new { |c| c.ssl_config.add_trust_ca("cacert1024.pem") }
     c.get("https://www.ruby-lang.org/")
     ```

     RSA 1024bit CA cert set is not maintained over years so you should
     consider updating OpenSSL version so that HTTPClient uses RSA 2048 bit
     CA cert set.

### Changes in 2.7.2

Apr 22, 2016 - version 2.7.2

 * Changes

   * Use RSA 1024bit CA cert when linked to old openssl

     Based on comments to #297 this commit silently (without warning) accepts
     RSA 1024bit certificate set when runtime ruby is liked with old OpenSSL
     (<1.0.1p or <1.0.2d.)

     If you're unsure that your OpenSSL is patched or not, and want to make
     sure to use RSA 2048bit certificate set, please call
     HTTPClient::SSLConfig#add_trust_ca("cacert.pem").

     ```ruby
     c = HTTPClient.new { |c| c.ssl_config.add_trust_ca("cacert.pem") }
     c.get("https://www.ruby-lang.org/")
     ```

     I'm going to remove RSA 1024bit certificate set and bump httpclient
     version to 2.8.0 soon after I release this as 2.7.2. I believe almost
     all OpenSSL installation is patched quickly these days so it should not
     cause SSL connectivity problem.

### Changes in 2.7.1

Jan 1, 2016 - version 2.7.1

 * Changes

   * Symbol aware header key comparison

     Normalizes symbol to String for header key.
     https://github.com/nahi/httpclient/issues/278

   * Show warning message only once

     Added HTTPClient::Util.warning that cached warning message and supress the
     message if it's already dumped.

   * Use Timeout.timeout instead of Kernel.timeout that is deprecated from ruby 2.3.0.

 * Bug fixes

   * [JRuby] Set ssl_version properly


### Changes in 2.7.0

Nov 5, 2015 - version 2.7.0

 * Changes

   * Update trusted CA certificates

     Issue #230 blocked updating trusted CA certificates to 2048 bit version
     long time. But from OpenSSL 1.0.1m and 1.0.2a it changes their custom
     chain building algorithm to find shortcut path when it fails to validate
     the path SSL server returns so that we can migrate trusted CA
     certificates to 2048bit version atop OpenSSL.

     Unfortunately the new algorithm has CVE-2015-1793 problem so we can use
     this new algorithm actually from OpenSSL >= 1.0.1p or >= 1.0.2d. (Jul
     2015)

     After this commit HTTPClient leverages 2048 bit version of trusted CA
     certificates if ruby is compiled with proper version of OpenSSL.

     ```ruby
     ver = OpenSSL::OPENSSL_VERSION
     if (ver.start_with?('OpenSSL 1.0.1') && ver >= 'OpenSSL 1.0.1p') ||
         (ver.start_with?('OpenSSL ') && ver >= 'OpenSSL 1.0.2d')
       filename = 'cacert.pem'
     else
       filename = 'cacert1024.pem'
      end
     ```

   * New SSLSocket implementation for JRuby

     Full rewrite of SSL implementation for JRuby with java.net.ssl.*.
     HTTPClient no longer relies on SSL implementation in jruby-openssl.
     Now it supports revocation check.

     On JRuby, instead of setting CRL by yourself you can set following
     options to let HTTPClient to perform revocation check with CRL and OCSP:

     ```
     -J-Dcom.sun.security.enableCRLDP=true -J-Dcom.sun.net.ssl.checkRevocation=true
     ex. % jruby -J-Dcom.sun.security.enableCRLDP=true -J-Dcom.sun.net.ssl.checkRevocation=true app.rb
     ```

   * HTTPClient.new accepts initialization block

     ```ruby
     HTTPClient.new { |c| c.debug_dev = STDERR }.get("...")
     ```

   * Add 'version' command to httpclient CLI

     ```
     % httpclient version
     2.7.0
     ```

   * Add patch() and patch_async() methods to support HTTP PATCH

 * Bug fixes

   * Support no header deflate compression

     Some server returns deflate content without zlib header. Try to detect
     it and fallback to plain deflate algorithm for
     transparent_gzip_decompression.  Fixes #244.


### Changes in 2.6.0

Jan 3, 2015 - version 2.6.0

This release includes internal CookieManager implementation change. It
involves compatibility layer but for the case your library depends on internal
implementation it also provides a way to restore the implementation. See below
for more details.

 * Changes

   * feat: use http-cookie if available for better Cookies spec compliance.

     Instead of WebAgent 0.6.2 that is not maintained over 10 years. To omit
     maintaining that library use http-cookie for better spec compliance and
     healthy development.

     This introduces following incompatibility from existing cookies
     implementation.

     * Expired cookies are not saved. With the old implementation expired
       cookies are saved in file and not be sent to the server. With the new
       implementation the expired cookies are not saved to the file and not
       be sent to the server.
     * Cookie#domain returns dot-less domain for domain cookies. Instead,
       Cookie#dot_domain returns with dot.

     http-cookie is used by default if available but you can restore original
     CookieManager behavior by loading 'httpclient/webagent-cookie' feature
     before 'httpclient' like this;

     ```ruby
     require 'httpclient/webagent-cookie'
     require 'httpclient'
     ```

     The new implementation dumps warnings to help you migrate to http-cookie.
     Please follow the suggestion to avoid future compatibility.

     ```ruby
     e.g.
      WebAgent::Cookie is deprecated and will be replaced with HTTP::Cookie in the near future. Please use Cookie#origin= instead of Cookie#url= for the replacement.
      Cookie#domain returns dot-less domain name now. Use Cookie#dot_domain if you need "." at the beginning.
      CookieManager#find is deprecated and will be removed in near future. Use HTTP::Cookie.cookie_value(CookieManager#cookies) instead
     ```

   * feat: Message#previous to get responses in negotiation

     HTTP::Message#previous keeps previous response in negotiation.  For
     redirection, authorization negotiation and retry from custom filter.
     Closes #234.

   * feat: Add JSONClient

     JSONClient auto-converts Hash <-> JSON in request and response.
     * For POST or PUT request, convert Hash body to JSON String with
       'application/json; charset=utf-8' header.
     * For response, convert JSON String to Hash when content-type is
       '(application|text)/(x-)?json'

     This commit include bin/jsonclient that works as same as bin/httpclient
     not with HTTPClient but with JSONClient.

   * feat: Add download command

     ```
     % httpclient download http://host/path > file
     ```

 * Bug fixes

   * fix: duplicated query params by follow_redirect

     When the original request has query and the server returns redirection
     response with Location, HTTPClient wrongly adds query to the new URI. In
     such case the Location header could include query part;

     ```
     e.g.
      http://originalhost/api/call?limit=10
      -> Location: http://otherhost/api/call?limit=10
     ```

     HTTPClient should just hit the new location '/api/call?limit=10' not
     '/api/call?limit=10&limit=10'. Closes #236.

   * fix: NTLM & Basic dual auth

     When a server returns two or more WWW-Authenticate headers and the first
     one is NTLM, say WWW-Authenticate: NTLM and WWW-Authenticate: Basic in
     this order, HTTPClient sent Basic Authorization header after finishing
     NTLM auth negotiation.

     NTLM auth is a connection authentication scheme so HTTPClient deleted
     the internal auth negotiation state so that NTLM authenticator does not
     do anything after the negotiation has completed. In such case, for the
     subsequent requests, NTLM authenticator does nothing but Basic
     authenticator sends Basic Authorization header to the server that is
     already negotiated via NTLM authenticator. This can cause authentication
     failure.

     This commit changes the internal state handling not to delete the state
     but introduce :done state. NTLM authenticator returns :skip for the
     request to the server that auth negotiation has completed. WWWAuth skips
     other authenticator to avoid above issue.  Closes #157.

   * fix: transplant IO positions to new request in negotiation

     In authorization negotiation HTTP::Message for request is generated for
     each request, of course, but HTTPClient did not care the IO position
     recorded in the previous requests in the subsequent requests.  Closes #130.

   * fix: avoid inconsistent Content-Length and actual body

     If lengths of all posted arguments are known HTTPClient sends
     'Content-Length' as a sum length of all arguments. But the length of
     actual body was wrong because it read as much as possible regardless of
     what IO#size returned. So if the file is getting bigger while HTTPClient
     is processing a request the request has inconsistent Content-Length and
     body.

     This bug is found, and the fix is proposed both by @Teshootub7. Thank
     you very much for patient trouble shooting!  Fixes #117.

   * fix: KeepAliveDisconnected race condition

     As details explained in #84, current HTTPClient's KeepAliveDisconnected
     handling has a race condition bug that allows a client to have
     invalidated connection two or more times. This could be a cause of #185.

     To avoid this, make HTTPClient acquire new connection for retry of
     KeepAliveDisconnected.  Closes #84. Closes #185.

### Changes in 2.5.3

This release includes behavior changes of POST and PUT requests that has
nil as a body. See changes below. Emtpty String as a body is not affected.

 * Changes

   * Update cacert. "Certificate data from Mozilla as of: Tue Oct 28 22:03:58 2014"
     -> Reverted in 2.5.3.3 because it caused unexpected SSLError. See
     https://github.com/nahi/httpclient/issues/230

   * Allow no content POST and PUT.
     Previously POST or PUT with :body => nil meant that 'POST or PUT with 0
     length entity body'. But sometimes you need to POST or PUT actually no
     content which should not have Content-Type nor Content-Length.
     It could be incompatible change for user who POST/PUT-ed with empty body
     but it should be rare, actually WEBrick cannot handle such 'no content'
     POST and PUT. #128.

   * Add default_header property.
     :default_header is for providing default headers Hash that all HTTP
     requests should have, such as custom 'Authorization' header in API.  You
     can override :default_header with :header Hash parameter in HTTP request
     methods.

   * raise if redirect res does not have Location header. #155.

 * Bug fixes

   * Avoid NPE by a cookie without domain=.
     The root cause is still uncertain though. Closes #123

   * Suppress verify_callback warning.
     Because OpenSSL can try multiple certificate chains and some of it can
     fail, and one of them succeeds. For that case warning is irrelevant.
     Let it warn only in $DEBUG mode. #221.

### Changes in 2.5.2

Oct 29, 2014 - version 2.5.2

  * Changes
    * Add :force_basic_auth config - #166, #179, #181.
	  Generally HTTP client must send Authorization header after it gets 401
	  error from server from security reason. But in some situation (e.g.
	  API client) you might want to send Authorization from the beginning.
	  You can turn on/off force_basic_auth flag for sending Authorization
	  header from the beginning. (Of cource, if a request URI matches with
	  the URI you set in set_auth method)

    Syntax:
    ```ruby
      HTTPClient.new(:force_basic_auth => true)
      # or
      c = HTTPClient.new
      c.force_basic_auth = true
    ```

    * Add :base_url to HTTPClient configuration.
    Passing path to get, post, etc. is recognized as a request to
    :base_url + uri.  If you pass full URL :base_url is ignored.

    ```ruby
      api = HTTPClient.new(:base_url => 'https://api.example.com/v1')
      api.get("/users.json") # => Get https://api.example.com/v1/users.json
      api.get("https://localhost/path") # => https://localhost/path
    ```


### Changes in 2.5.1

Oct 19, 2014 - version 2.5.1

  * Changes
	* Allow to specify :query in POST, PUT, DELETE and OPTIONS requests.
      Closes #83.
    * Allow to specify :body in OPTIONS request. Closes #136.


### Changes in 2.5.0

Oct 17, 2014 - version 2.5.0

**IMPORTANT CHANGES**

This version changes (again) default SSL options to help
BEAST/CRIME/POODLE Attack prevension.

 * Disabled SSLv3 in favor of POODLE Attack prevention.
 * Enabled 1/n-1 fragment in favor of BEAST Attack prevention.
 * No TLS compression in favor of CRIME Attack prevention.

You can restore the previous SSL configuration like this;

```ruby
client = HTTPClient.new
client.ssl_config.ssl_version = :SSLv23
client.ssl_config.options = OpenSSL::SSL::OP_ALL | OpenSSL::SSL::OP_NO_SSLv2
```

  * Changes
	* Change default SSL options. See above.
    * Keep cause error of KeepAliveDisconnected. It allows caller to
	  investigate the cause of KeepAliveDisconnected.


### Changes in 2.4.0

Jun 8, 2014 - version 2.4.0

**IMPORTANT CHANGES**

This version changes default SSL version to :auto (same as nil) to use SSL/TLS
version negotiation.  Former versions use SSLv3 as default that does not connect
via TLS.  This change makes underlying OpenSSL library decide which SSL/TLS
version to use but SSLv2 is disabled.

This change makes your secure connection safer but if you see SSL connection
failure with this version try specifying SSL version to use SSLv3 like;
```
client = HTTPClient.new
client.ssl_config.ssl_version = :SSLv3
```

  * Bug fixes
    * Avoid unnecessary connection retries for OAuth error.
      [#203](https://github.com/nahi/httpclient/issues/203)
	* Make authentication drivers Thread-safe.  Note that HTTPClient instance is
	  Thread-safe for authentication state update but it shares authentication
	  state across threads by design.  If you don't want to share authentication
	  state, such as for using different authentication username/password pair
	  per thread, create HTTPClient instance for each Thread.
      [#200](https://github.com/nahi/httpclient/issues/200)
    * Avoid chunked String recycle in callback block.
      [#193](https://github.com/nahi/httpclient/issues/193)
    * Do not send empty 'oauth_token' in signed request for compatibility.
      [#188](https://github.com/nahi/httpclient/issues/188)
    * Ignore negative Content-Length header from server.
      [#175](https://github.com/nahi/httpclient/issues/175)
    * Fix incorrect use of absolute URL for HTTPS proxy requests.
      [#168](https://github.com/nahi/httpclient/issues/168)
    * Handle UTF characters in chunked bodies.
      [#167](https://github.com/nahi/httpclient/issues/167)
    * A new cookie never be accepted if an HTTPClient has the same expired cookie.
      [#154](https://github.com/nahi/httpclient/issues/154)
	* Allow spaces in NO_PROXY environment like; "hosta, hostb"
      [#141](https://github.com/nahi/httpclient/issues/141)
	* Avoid HttpClient::Message::Body#dump causes Encoding::CompatibilityError.
      [#140](https://github.com/nahi/httpclient/issues/140)

  * Changes
	* Change default SSL version to :auto to use version negotiation.
      [#186](https://github.com/nahi/httpclient/issues/186),
      [#204](https://github.com/nahi/httpclient/issues/204)
    * Allow to pass client private key passphrase in SSLConfig.
      [#201](https://github.com/nahi/httpclient/issues/201)
    * Convert README to markdown syntax
      [#198](https://github.com/nahi/httpclient/issues/198)
    * Update default CA certificates: change the source from JDK's to Firefox's.
      The file is downloaded from
	  https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt
	  (Certificate data from Mozilla as of: Tue Apr 22 08:29:31 2014)
      [#195](https://github.com/nahi/httpclient/issues/195)
	* Callback block can be defined as to get 2 arguments to retrieve the
	  response object.
      [#194](https://github.com/nahi/httpclient/issues/194)
    * Remove [] from given address for IPv6 compat.
      [#176](https://github.com/nahi/httpclient/issues/176)
    * Update API endpoints to those of Twitter REST API v1.1.
      [#150](https://github.com/nahi/httpclient/issues/150)


### Changes in 2.3.4

July 27, 2013 - version 2.3.4

  * Bug fixes
    * Make sure to read socket in BINARY buffer.
	  [#171](https://github.com/nahi/httpclient/issues/171)

### Changes in 2.3.3

February 24, 2013 - version 2.3.3

  * Changes

	* Add User-Agent field by default. You can remove the header by setting nil
	  to HTTPClient#agent_name.
      [#144](https://github.com/nahi/httpclient/issues/144)

### Changes in 2.3.2

January 5, 2013 - version 2.3.2

```
  * Changes

    * #138 Revert Timeout change unintentionally included in v2.3.1.  It's
      reported that the change causes background processes not terminated
      properly.
```

### Changes in 2.3.1

January 1, 2013 - version 2.3.1

```
  * Changes

    * #137 Signing key is expiring for cacert_sha1.p7s.
      Deleted p7s signature check for default cacerts.  Sorry for many troubles
      in the past. This feature is not useful without having online/real-time
      CA certs update but I don't think I can implement it in near future.
      Users depend on this signature check (who puts cacert.p7s in R/W
      filesystem and ssl_config.rb in R/O filesystem) should take care the
      tampering by themself.

  * Bug fixes

    * #122 Support IPv6 address in URI
```


### Changes in 2.3.0

October 10, 2012 - version 2.3.0

```
    * Features

      * Added debug mode CLI.  bin/httpclient is installed as CLI.
          Usage: 1) % httpclient get https://www.google.co.jp/ q=ruby
          Usage: 2) %httpclient
        For 1) it issues a GET request to the given URI and shows the wiredump
        and the parsed result.  For 2) it invokes irb shell with the binding
        that has a HTTPClient as 'self'.  You can call HTTPClient instance
        methods like;
          > get "https://www.google.co.jp/", :q => :ruby

      * #119 Addressable gem support (only if it exists); should handle IRI
        properly.

    * Bug fixes

      * #115 Cookies couldn't work properly if the path in an URI is ommited.
      * #112, #117 Proper handling of sized IO (the IO object that responds to
        :size) for chunked POST. HTTPClient did read till EOF even if the
        given IO has :size method.
      * Handle '303 See Other' properly.  RFC2616 says it should be redirected
        with GET.
      * #116 Fix "100-continue" support.  It was just ignored.
      * #118 Support for boolean values when making POST/PUT requests with
        multiipart/form Content-Type.
      * #110 Allows leading dots in no_proxy hostname suffixes.
```

### Changes in 2.2.7

August 14, 2012 - version 2.2.7

```
    * Bug fixes

      * Fix arity incompatibility introduced in 2.2.6.  It broke Webmock.
        Thanks Andrew France for the report!
```

### Changes in 2.2.6

August 14, 2012 - version 2.2.6

```
    * Bug fixes

      * Make get_content doesn't raise a BadResponseError for perfectly good
        responses like 304 Not Modified. Thanks to Florian Hars.

      * Add 'Content-Type: application/x-www-form-urlencoded' for the PUT
        request that has urlencoded entity-body.

    * Features

      * Add HTTPClient::IncludeClient by Jonathan Rochkind, a mix-in for easily
        adding a thread-safe lazily initialized class-level HTTPClient object
        to your class.

      * Proxy DigestAuth support. Thanks to Alexander Kotov and Florian Hars.

      * Accept an array of strings (and IO-likes) as a query value
        e.g. `{ x: 'a', y: [1,2,3] }` is encoded into `"x=a&y=1&y=2&y=3"`.
        Thanks to Akinori MUSHA.

      * Allow body for DELETE method.

      * Allow :follow_redirect => true for HEAD request.

      * Fill request parameters request_method, request_uri and request_query
        as part of response Message::Header.
```

### Changes in 2.2.5

  May 06, 2012 - version 2.2.5

```
    * Bug fixes

      * Added Magic encoding comment to hexdump.rb to avoid encoding error.
      * Add workaround for JRuby issue on Windows (JRUBY-6136)
        On Windows, calling File#size fails with an Unknown error (20047).
        This workaround uses File#lstat instead.
      * Require open-uri only on ruby 1.9, since it is not needed on 1.8.

    * Features

      * Allow symbol Header name for HTTP request.
      * Dump more SSL certificate information under $DEBUG.
      * Add HTTPClient::SSLConfig#ssl_version property.
      * Add 'Accept: */*' header to request by default. Rails requies it.
        It doesn't override given Accept header from API.
      * Add HTTPClient::SSLConfig#set_default_paths. This method makes
        HTTPClient instance to use OpenSSL's default trusted CA certificates.
      * Allow to set Date header manually.
        ex. clent.get(uri, :header => {'Date' => Time.now.httpdate})
```

### Changes in 2.2.4

  Dec 08, 2011 - version 2.2.4

```
    * Bug fixes

      * Do not recycle buffer String object for yielding.  When the response is
        not chunked and the size of the response > 16KB, API with block style
        yields recycled String object for each yields.

      * Set VERSION string in User-Agent header.  $Id$ didn't work long time...

      Bugs are reported by Seamus Abshere. Thanks!
```

### Changes in 2.2.3

  Oct 28, 2011 - version 2.2.3

```
    * Bug fixes

      * Ruby 1.8.6 support.  It's broken from 2.2.0.
```

### Changes in 2.2.2

  Oct 17, 2011 - version 2.2.2

```
    * Bug fixes

      * Do not sort query params on request: Wrongly sorted query params for
        easier debugging but the order of request parameter should be
        preserved. #65

    * Changes

      * Set responce String encoding if possible.  Parse content-type response
        header with some helps from OpenURI::Meta and set response String
        encoding. #26

      * Improve connection cache strategy.  Reuse cached session in MRU order,
        not in LRU.  MRU is more server friendly than LRU because it reduces
        number of cached sessions when a number of requests drops after an
        usaage spike.

        With reusing sessions in LRU order, all sessions are equally checked if
        it's closed or not, as far as there's a request to the same site.  With
        reusing sessions in MRU order, old cold sessions are kept in cache long
        time even if there's a request to the same site.  To avoid this leakage,
        this version adds keep_alive_timeout property and let SessionManager
        scrub all sessions with checking the timeout for each session.  When the
        session expires against the last used time, it's closed and collected.

        keep_alive_timeout is 15[sec] by default. The value is from the default
        value for KeepAliveTimeout of Apache httpd 2.  #68 #69
```

### Changes in 2.2.1

  Jun 2, 2011 - version 2.2.1

```
    * Bug fixes

      * For Lighttpd + PUT/POST support, do not send a request using chunked
        encoding when IO respond to :size, File for example.

        - There is no need to send query with Transfer-Encoding: chuncked when
          IO respond to :size.
        - Lighttpd does not support PUT, POST with Transfer-Encoding: chuncked.
          You will see that the lighty respond with 200 OK, but there is a file
          whose size is zero.

        LIMITATION:
          timeout occurs certainly when you send very large file and
          @send_timeout is default since HTTPClient::Session#query() assumes
          that *all* write are finished in @send_timeout sec not each write.

        WORKAROUND:
          increment @send_timeout and @receive_timeout or set @send_timeout and
          @receive_timeout to 0 not to be timeout.

        This fix is by TANABE Ken-ichi <nabeken@tknetworks.org>. Thanks!

      * Allow empty http_proxy ENV variable. Just treat it the same as if it's
        nil/unset. This fix is by Ash Berlin <ash_github@firemirror.com>.
        Thanks!

      * Check EOF while reading chunked response and close the session. It
        raised NoMethodError.

    * Changes

      * Updated trusted CA certificates file (cacert.p7s and cacert_sha1.p7s).
        CA certs are imported from
        'Java(TM) SE Runtime Environment (build 1.6.0_25-b06)'.

      * Changed default chunk size from 4K to 16K. It's used for reading size
        at a time.
```

### Changes in 2.2.0

  Apr 8, 2011 - version 2.2.0

```
    * Features
      * Add HTTPClient#cookies as an alias of #cookie_manager.cookies.

      * Add res.cookies method. It returns parsed cookie in response header.
        It's different from client.cookie_manager.cookies. Manager keeps
        persistent cookies in it.

      * Add res.headers method which returns a Hash of headers.
        Hash key and value are both String. Each key has a single value so you
        can't extract exact value when a message has multiple headers like
        'Set-Cookie'. Use header['Set-Cookie'] for that purpose.
        (It returns an Array always)

      * Allow keyword style argument for HTTPClient#get, post, etc.
        Introduced keywords are: :body, :query, and :header.
        You can write
          HTTPClient.get(uri, :header => {'X-custom' => '1'})
        instead of;
          HTTPClient.get(uri, nil, {'X-custom' => '1'})

      * Add new keyword argument :follow_redirect to get/post. Now you can
        follow redirection response with passing :follow_redirect => true.

      * [INCOMPAT] Rename HTTPClient::HTTP::Message#body to #http_body, then
        add #body as an alias of #content. It's incompatible change though
        users rarely depends on this method. (I've never seen such a case)
        Users who are using req.body and/or res.body should follow this
        change. (req.http_body and res.http_body)

    * Bug fixes

      * Reenable keep-alive for chunked response.
        This feature was disabled by c206b687952e1ad3e20c20e69bdbd1a9cb38609e at
        2008-12-09. I should have written a test for keep-alive. Now I added it.
        Thanks Takahiro Nishimura(@dr_taka_n) for finding this bug.
```

### Changes in 2.1.7

  Mar 22, 2011 - version 2.1.7

```
    * Features
      * Add MD5-sess auth support. Thanks to wimm-dking. (#47)
      * Add SNI support. (Server Name Indication of HTTPS connection) (#49)
      * Add GSSAPI auth support using gssapi gem. Thanks to zenchild. (#50)
      * NTLM logon to exchange Web Services. [experimental] Thanks to curzonj and mccraigmccraig (#52)
      * Add HTTPOnly cookie support. Thanks to nbrosnahan. (#55)
      * Add HTTPClient#socket_local for specifying local binding hostname and port of TCP socket. Thanks to icblenke.
```

### Changes in 2.1.6

  Dec 20, 2010 - version 2.1.6

```
    * IMPORTANT update for HTTPS(SSL) connection
      * Trusted CA bundle file cacert_sha1.p7s for older environment (where
        you cannot use SHA512 algorithm such as an old Mac OS X) included in
        httpclient 2.1.5 expires in Dec 31, 2010.  Please update to 2.1.6 if
        you're on such an environment.
      * Updated trusted CA certificates file (cacert.p7s and cacert_sha1.p7s).
        CA certs are imported from
        'Java(TM) SE Runtime Environment (build 1.6.0_22-b04)'.

    * IMPORTANT bug fix for persistent connection
      * #29 Resource Leak: If httpclient establishes two connections to the
        same server in parallel, one of these connections will be leaked, patch
        by xb.
      * #30 When retrying a failed persistent connection, httpclient should use
        a fresh connection, reported by xb.
        These 2 fixes should fix 'Too many open files' error as well if you're
        getting this. Please check 2.1.6 and let me know how it goes!

    * Features
      * #4 Added OAuthClient. See sample clients in sample/ dir.
      * #42 Added transparent_gzip_decompression property, patch by Teshootub7.
        All you need to use it is done by;
        client.transparent_gzip_decompression = true
        Then you can retrieve a document as usural in decompressed format.
      * #38 Debug dump binary data (checking it includes \0 or not) in hex
        encoded format, patch by chetan.

    * Bug fixes
      * #8 Opened certificate and key files for SSL not closed properly.
      * #10 "get" method gets blocked in "readpartial" when receiving a 304
        with no Content-Length.
      * #11 Possible data corruption problem in asynchronous methods, patch by
        a user. (http://dev.ctor.org/http-access2/ticket/228)
      * #13 illegal Cookie PATH handling. When no PATH part given in Set-Cookie
        header, URL's path part should be used for path variable.
      * #16 httpclient doesn't support multiline server headers.
      * #19 set_request_header clobbers 'Host' header setting if given, patch
        by meuserj.
      * #20 Relative Location on https redirect fails, patch by zenchild.
      * #22 IIS/6 + MicrosoftSharePointTeamServices uses "NTLM" instead of
        "Negotiate".
      * #27 DigestAuth header: 'qop' parameter must not be enclosed between
        double quotation, patch by ibc.
      * #36 Wrong HTTP version in headers with Qt4 applications, reported by
        gauleng.
      * #38 DigestAuth + posting IO fails, patch by chetan.
      * #41 https-over-proxy fails with IIS, patch by tai.
```

### Changes in 2.1.5

  Jun 25, 2009 - version 2.1.5.2

```
    * Added another cacert distribution certificate which uses
      sha1WithRSAEncryption.  OpenSSL/0.9.7 cannot handle non-SHA1 digest
      algorithm for certificate.  The new certificate is
      RSA 2048 bit + SHA1 + notAfter:2010/12/31.  Corresponding CA bundle file
      is cacert_sha1.p7s.  It is loaded only when cacert.p7s cannot be loaded
      with the original distribution certificate.
```

  Jun 11, 2009 - version 2.1.5.1

```
    * README update.
```

  Jun 8, 2009 - version 2.1.5

```
    * IMPORTANT update for HTTPS(SSL) connection
      * Trusted CA bundle file included in httpclient <= 2.1.4 expires in
        Nov 2009. Please update to 2.1.5 by Oct 2009 if your application
        depends on trusted CA bundle file.
      * Updated trusted CA certificates file (cacert.p7s). CA certs are
        imported from 'Java(TM) SE Runtime Environment (build 1.6.0_13-b03)'.
      * Updated a cacert distribution certificate.
        RSA 2048 bit + SHA512 + notAfter:2037/12/31. (#215)

    * Feature
      * WWW authentication with Negotiate based on win32/sspi as same as Proxy
        authentication. Applied a patch from Paul Casto. Thanks! (#212)

    * Bug fixes
      * Infinite loop caused by EOF error while reading response message body
        without Content-Length.  IO#readpartial does not clear the second
        argument (buffer) when an exception raised.  Fixed by a patch from an
        user.  Thanks! (#216)
      * NoMethodError caused by the cookie string that includes a double
        semicolons ";;".  Fixed by a patch from an user.  Thanks! (#211)
      * CNONCE attribute in Digest Authentication was not properly generated by
        itself (used same nonce sent from the connecting server). Fixed by a
        patch from bterlson
        [http://github.com/bterlson/httpclient/commit/6d0df734840985a7be88a2d54443bbf892d50b9a]
        Thanks! (#209)
      * Cookie header was not set in authentication negotiation. Fixed. This
        bug was found and pointed out by bterlson at
        [http://github.com/bterlson/httpclient/commits/master]. Thanks! (#210)
      * Do not send 'Content-Length: 0' when a request doesn't have message
        body. Some server application (!EasySoap++/0.6 for example) corrupts
        with the request with Content-Length: 0. This bug was found by clay
        [http://daemons.net/~clay/2009/05/03/ruby-why-do-you-torment-me/].
        Thanks! (#217)
      * Ensure to reset connection after invoking HTTPClient singleton methods
        for accessing such as HTTPClient.get_content. Thanks to @xgavin! (#214)
```

### Changes in 2.1.4

  Feb 13, 2009 - version 2.1.4

```
    * Bug fixes
      * When we hit some site through http-proxy we get a response without
        Content-Length header.  httpclient/2.1.3 drops response body for such
        case. fixed. (#199)
      * Avoid duplicated 'Date' header in request. Fixed. (#194)
      * Avoid to add port number to 'Host' header.  Some servers like GFE/1.3
        dislike it. Thanks to anonymous user for investigating the behavior.
        (#195)
      * httpclient/2.1.3 does not work when you fork a process after requiring
        httpclient module (Passenger). Thanks to Akira Yamada for tracing down
        this bug. (#197)
      * httpclient/2.1.3 cannot handle Cookie header with 'expires=' and
        'expires=""'.  Empty String for Time.parse returns Time.now unlike
        ParseDate.parsedate. Thanks to Mark for the patch. (#200)
```

### Changes in 2.1.3

  Jan 8, 2009 - version 2.1.3.1

```
    * Security fix introduced at 2.1.3.
      * get_content/post_content of httpclient/2.1.3 may send secure cookies
        for a https site to non-secure (non-https) site when the https site
        redirects the request to a non-https site.  httpclient/2.1.3 caches
        request object and reuses it for redirection.  It should not be cached
        and recreated for each time as httpclient <= 2.1.2 and http-access2.
      * I realized this bug when I was reading open-uri story on
        [ruby-core:21205].  Ruby users should use open-uri rather than using
        net/http directly wherever possible.
```

  Dec 29, 2008 - version 2.1.3

```
    * Features
      * Proxy Authentication for SSL.
      * Performance improvements.
      * Full RDoc. Please tell me any English problem. Thanks in advance.
      * Do multipart file upload when a given body includes a File. You don't
        need to set 'Content-Type' and boundary String any more.
      * Added propfind and proppatch methods.

    * Changes
      * Avoid unnecessary memory consuming for get_content/post_content with
        block.  get_content returns nil when you call it with a block.
      * post_content with IO did not work when redirect/auth cycle is required.
        (CAUTION: post_content now correctly follows redirection and posts the
        given content)
      * Exception handling cleanups.
        * Raises HTTPClient::ConfigurationError? for environment problem.
          (trying to do SSL without openssl installed for example)
        * Raises HTTPClient::BadResponse? for HTTP response problem.  You can
          get the response HTTPMessage returned via $!.res.
        * Raises SocketError? for connection problem (as same as before).

    * Bug fixes
      * Avoid unnecessary negotiation cycle for Negotiate(NTLM) authentication.
        Thanks Rishav for great support for debugging Negotiate authentication.
      * get_content/post_content with block yielded unexpected message body
        during redirect/auth cycle.
      * Relative URI redirection should be allowed from 2.1.2 but it did not
        work... fixed.
      * Avoid unnecessary timeout waiting when no message body returned such as
        '204 No Content' for DAV.
      * Avoid blocking on socket closing when the socket is already closed by
        foreign host and the client runs under MT-condition.
```

### Changes in 2.1.2

  Sep 22, 2007 - version 2.1.2

```
    * HTTP
      * implemented Negotiate authentication with a support from exterior
        modules. 'rubyntlm' module is required for Negotiate auth with IIS.
        'win32/sspi' module is required for Negotiate auth with ISA.
      * a workaround for Ubuntu + SonicWALL timeout problem. try to send HTTP
        request in one chunk.

    * SSL
      * create new self-signing dist-cert which has serial number 0x01 and
        embed it in httpclient.rb.
      * update cacert.p7s. certificates are imported from cacerts in JRE 6
        Update 2. 1 expired CA certificate
        'C=US, O=GTE Corporation, CN=GTE CyberTrust Root' is removed.

    * Bug fix
      * [BUG] SSL + debug_dev didn't work under version 2.1.1.
      * [BUG] Reason-Phrase of HTTP response status line can be empty according
      * to RFC2616.
```

### Changes in 2.1.1

  Aug 28, 2007 - version 2.1.1

```
    * bug fix
      * domain_match should be case insensitive. thanks to Brian for the patch.
      * before calling SSLSocket#post_connection_check, check if
        RUBY_VERSION > "1.8.4" for CN based wildcard certificate. when
        RUBY_VERSION <= "1.8.4",  it fallbacks to the post_connection_check
        method in HTTPClient so httpclient should run on 1.8.4 fine as before.

    * misc
      * added HTTPClient#test_loopback_http_response which accepts test
        loopback response which contains HTTP header.
```

### Changes in 2.1.0

  Jul 14, 2007 - version 2.1.0

```
    * program/project renamed from 'http-access2' to 'httpclient'.
      there's compatibility layer included so existing programs for
      http-access2 which uses HTTPAccess2::Client should work with
      httpclient/2.1.0 correctly.

    * misc
      * install.rb did not install cacerts.p7s.  Thanks to knu.
      * now HTTPClient loads http_proxy/HTTP_PROXY and no_proxy/NO_PROXY
        environment variable at initialization time. bear in mind that it
        doesn't load http_proxy/HTTP_PROXY when a library is considered to be
        running under CGI environment (checked by ENVREQUEST_METHOD existence.
        cgi_http_proxy/CGI_HTTP_PROXY is loaded instead.
```

### Changes in 2.0.9

  Jul 4, 2007 - version 2.0.9

```
    * bug fix
      * fix the BasicAuth regression problem in 2.0.8.  A server may return
        "BASIC" as an authenticate scheme label instead of "Basic".  It must be
        treated as a case-insensitive token according to RFC2617 section 1.2.
        Thanks to mwedeme for contributing the patch. (#159)
```

### Changes in 2.0.8

  Jun 30, 2007 - version 2.0.8

```
    * HTTP
      * added request/response filter interface and implemented DigestAuth
        based on the filter interface.  DigestAuth calc engine is based on
        http://tools.assembla.com/breakout/wiki/DigestForSoap
        Thanks to sromano. (#155)
      * re-implemented BasicAuth based on the filter interface.  send BasicAuth
        header only if it's needed. (#31)
      * handle a response which has 2XX status code as a successfull response
        while retry check.  applied the patch from Micah Wedemeyer.
        Thanks! (#158)

    * Connection
      * show more friendly error message for unconnectable URL. (#156)

    * bug fixes
      * to avoid MIME format incompatibility, add empty epilogue chunk
        explicitly.  Thanks to the anonymous user who reported #154 (#154)
      * rescue EPIPE for keep-alive reconnecting.  Thanks to anonymous user
        who posted a patch at #124. (#124)
```

### Changes in 2.0.7

  May 13, 2007 - version 2.0.7

```
    * HTTP
      * added proxyauth support. (#6)
      * let developer allow to rescue a redirect with relative URI. (#28)
      * changed last-chunk condition statement to allow "0000\r\n" marker from
        WebLogic Server 7.0 SP5 instead of "0\r\n". (#30)
      * fixed multipart form submit. (#29, #116)
      * use http_date format as a date in a request header. (#35)
      * avoid duplicated Date header when running under mod_ruby. (#127)
      * reason phrase in Message#reason contains \r. (#122)
      * trim "\n"s in base64 encoded BasicAuth value for interoperability.
        (#149)
      * let retry_connect return a Message not a content. (#119)
      * rescue SocketError and dump a message when a wrong address given. (#152)

    * HTTP-Cookies
      * changed "domain" parameter matching condition statement to allow
        followings; (#24, #32, #118, #147)
        * [host, domain] = [rubyforge.com, .rubyforge.com]
        * [host, domain] = [reddit.com, reddit.com]

    * SSL
      * bundles CA certificates as trust anchors.
      * allow user to get peer_cert. (#117, #123)
      * added wildcard certificate support. (#151)
      * SSL + HTTP keep-alive + long wait causes uncaught exception.  fixed.
        (#120)

    * Connection
      * fixed a loop condition bug that caused intermittent empty response.
        (#150, #26, #125)
```

### Changes in 2.0.6

  September 16, 2005 - version 2.0.6

```
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
```

### Changes in 2.0.5

  December 24, 2004 - version 2.0.5

```
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
```

### Changes in 2.0.4

  February 11, 2004 - version 2.0.4

```
    - add Client#redirect_uri_callback interface.
    - refactorings and bug fixes found during negative test.
    - add SSL test.
```

### Changes in 2.0.3

  December 16, 2003 - version 2.0.3

```
    - no_proxy was broken in 2.0.2.
    - do not dump 'Host' header under protocol_version == 'HTTP/1.0'
```

### Changes in 2.0.2

  December ?, 2003 - version 2.0.2

```
    - do not trust HTTP_PROXY environment variable. set proxy server manually.
      http://ftp.ics.uci.edu/pub/websoft/libwww-perl/archive/2001h1/0072.html
      http://ftp.ics.uci.edu/pub/websoft/libwww-perl/archive/2001h1/0241.html
      http://curl.haxx.se/mail/archive-2001-12/0034.html
    - follow ossl2 change.
```

### Changes in 2.0.1

  October 4, 2003 - version 2.0.1

```
    Query was not escaped when query was given as an Array or a Hash.  Fixed.
    Do not use http_proxy defined by ENV['http_proxy'] or ENV['HTTP_PROXY'] if
      the destination host is 'localhost'.
    Hosts which matches ENV['no_proxy'] or ENV['NO_PROXY'] won't be proxyed.
      [,:] separated. ("ruby-lang.org:rubyist.net")
      No regexp. (give "ruby-lang.org", not "*.ruby-lang.org")
      If you want specify hot by IP address, give full address.
        ("192.168.1.1, 192.168.1.2")
```

### Changes in 2.0

  September 10, 2003 - version 2.0

```
    CamelCase to non_camel_case.
    SSL support (requires Ruby/OpenSSL).
    Cookies support.  lib/http-access2/cookie.rb is redistributed file which is
      originally included in Webagent by TAKAHASHI `Maki' Masayoshi.  You can
      download the entire package from http://www.rubycolor.org/arc/.
```

  January 11, 2003 - version J

```
    ruby/1.8 support.
```
