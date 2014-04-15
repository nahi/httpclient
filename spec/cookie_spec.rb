# coding: utf-8
require 'spec_helper'

require 'uri'
require 'httpclient/cookie'

describe 'Cookies' do
  before :each do
    @c = WebAgent::Cookie.new()
  end

  it { @c.should be_an_instance_of WebAgent::Cookie }

  it '#discard' do
    (!!@c.discard?).should be_false
    @c.discard = true
    (!!@c.discard?).should be_true
  end

  it '#match?' do
    url = urify('http://www.rubycolor.org/hoge/funi/#919191')

    @c.domain = 'www.rubycolor.org'
    @c.match?(url).should be_true

    @c.domain = '.rubycolor.org'
    @c.match?(url).should be_true

    @c.domain = 'aaa.www.rubycolor.org'
    @c.match?(url).should be_false

    @c.domain = 'aaa.www.rubycolor.org'
    @c.match?(url).should be_false

    @c.domain = 'www.rubycolor.org'
    @c.path = '/'
    @c.match?(url).should be_true

    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    @c.match?(url).should be_true

    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge/hoge'
    @c.match?(url).should be_false

    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    @c.secure = true
    @c.match?(url).should be_false

    url2 = urify('https://www.rubycolor.org/hoge/funi/#919191')
    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    @c.secure = true
    @c.match?(url2).should be_true

    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    @c.secure = nil
    @c.match?(url2).should be_true

    url.port = 80
    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    @c.match?(url).should be_true

    url_nopath = URI.parse('http://www.rubycolor.org')
    @c.domain = 'www.rubycolor.org'
    @c.path = '/'
    @c.match?(url_nopath).should be_true
  end

  it '#head_match?' do
    @c.head_match?("","").should be_true
    @c.head_match?("a","").should be_false
    @c.head_match?("","a").should be_true
    @c.head_match?("abcde","abcde").should be_true
    @c.head_match?("abcde","abcdef").should be_true
    @c.head_match?("abcdef","abcde").should be_false
    @c.head_match?("abcde","bcde").should be_false
    @c.head_match?("bcde","abcde").should be_false
  end

  it 'tail_match?' do
    @c.tail_match?("","").should be_true
    @c.tail_match?("a","").should be_false
    @c.tail_match?("","a").should be_true
    @c.tail_match?("abcde","abcde").should be_true
    @c.tail_match?("abcde","abcdef").should be_false
    @c.tail_match?("abcdef","abcde").should be_false
    @c.tail_match?("abcde","bcde").should be_false
    @c.tail_match?("bcde","abcde").should be_true
  end


  it 'domain_match' do
    extend WebAgent::CookieUtils
    (!!domain_match("hoge.co.jp",".")).should be_true
    (!!domain_match("192.168.10.1","192.168.10.1")).should be_true
    (!!domain_match("192.168.10.1","192.168.10.2")).should be_false
    (!!domain_match("hoge.co.jp",".hoge.co.jp")).should be_true
    (!!domain_match("www.hoge.co.jp", "www.hoge.co.jp")).should be_true
    (!!domain_match("www.hoge.co.jp", "www2.hoge.co.jp")).should be_false
    (!!domain_match("www.hoge.co.jp", ".hoge.co.jp")).should be_true
    (!!domain_match("www.aa.hoge.co.jp", ".hoge.co.jp")).should be_true
    (!!domain_match("www.hoge.co.jp", "hoge.co.jp")).should be_false
  end

  it 'join_quotedstr' do
    arr1 = ['hoge=funi', 'hoge2=funi2']
    arr1.should eq @c.instance_eval{join_quotedstr(arr1,';')}
    arr2 = ['hoge="fu', 'ni"',  'funi=funi']
    ['hoge="fu;ni"','funi=funi'].should eq @c.instance_eval{join_quotedstr(arr2,';')}
    arr3 = ['hoge="funi";hoge2="fu','ni2";hoge3="hoge"',  'funi="funi"']
    ['hoge="funi";hoge2="fu,ni2";hoge3="hoge"',  'funi="funi"'].should eq @c.instance_eval{join_quotedstr(arr3,',')}
  end
end


describe 'CookieManager' do
  before :each do
    @cm = WebAgent::CookieManager.new()
  end

  it 'parse' do
    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; expires=Wed, 01-Dec-2010 00:00:00 GMT; path=/"
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    cookie.should be_an_instance_of WebAgent::Cookie
    cookie.name.should eq "inkid"
    cookie.value.should eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    cookie.expires.should eq Time.gm(2010, 12, 1, 0,0,0)
    cookie.path.should eq "/"
  end

  it 'parse2' do
    str = "xmen=off,0,0,1; path=/; domain=.excite.co.jp; expires=Wednesday, 31-Dec-2037 12:00:00 GMT"
    @cm.parse(str, urify('http://www.excite.co.jp'))
    cookie = @cm.cookies[0]
    cookie.should be_an_instance_of WebAgent::Cookie
    cookie.name.should eq "xmen"
    cookie.value.should eq "off,0,0,1"
    cookie.domain.should eq ".excite.co.jp"
    cookie.expires.should eq Time.gm(2037,12,31,12,0,0)
    cookie.path.should eq "/"

    cookie.secure?.should be_false
    cookie.http_only?.should be_false
  end

  it 'parse3' do
    str = "xmen=off,0,0,1; path=/; domain=.excite.co.jp; expires=Wednesday, 31-Dec-2037 12:00:00 GMT;Secure;HTTPOnly"
    @cm.parse(str, urify('http://www.excite.co.jp'))
    cookie = @cm.cookies[0]
    cookie.should be_an_instance_of WebAgent::Cookie
    cookie.name.should eq "xmen"
    cookie.value.should eq "off,0,0,1"
    cookie.domain.should eq ".excite.co.jp"
    cookie.expires.should eq Time.gm(2037,12,31,12,0,0)
    cookie.path.should eq "/"
    cookie.secure?.should be_true
    cookie.http_only?.should be_true
  end

  it 'parse_double_semicolon' do
    str = "xmen=off,0,0,1;; path=\"/;;\"; domain=.excite.co.jp; expires=Wednesday, 31-Dec-2037 12:00:00 GMT"
    @cm.parse(str, urify('http://www.excite.co.jp'))
    cookie = @cm.cookies[0]
    cookie.should be_an_instance_of WebAgent::Cookie
    cookie.name.should eq "xmen"
    cookie.value.should eq "off,0,0,1"
    cookie.domain.should eq ".excite.co.jp"
    cookie.expires.should eq Time.gm(2037,12,31,12,0,0)
    cookie.path.should eq "/;;"
  end

  it 'check_expired_cookies' do
    c1 = WebAgent::Cookie.new()
    c2 = c1.dup
    c3 = c1.dup
    c4 = c1.dup
    c1.expires = Time.now - 100
    c2.expires = Time.now + 100
    c3.expires = Time.now - 10
    c4.expires = nil
    cookies = [c1,c2,c3,c4]
    @cm.cookies = cookies
    @cm.check_expired_cookies()
    # expires == nil cookies (session cookie) exists.
    @cm.cookies.should eq [c2,c4]
  end

  it 'parse_expires' do
    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; expires=; path=/"
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    cookie.should be_an_instance_of WebAgent::Cookie
    cookie.name.should eq "inkid"
    cookie.value.should eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    cookie.expires.should be_nil
    cookie.path.should eq "/"

    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; path=/; expires="
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    cookie.should be_an_instance_of WebAgent::Cookie
    cookie.name.should eq "inkid"
    cookie.value.should eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    cookie.expires.should be_nil
    cookie.path.should eq "/"

    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; path=/; expires=\"\""
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    cookie.should be_an_instance_of WebAgent::Cookie
    cookie.name.should eq "inkid"
    cookie.value.should eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    cookie.expires.should be_nil
    cookie.path.should eq "/"
  end

  it 'parse_after_expiration' do
    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; expires=Wed, 01-Dec-2010 00:00:00 GMT; path=/"
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    cookie.should be_an_instance_of WebAgent::Cookie
    cookie.name.should eq "inkid"
    cookie.value.should eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    cookie.expires.should eq Time.gm(2010, 12, 1, 0,0,0)
    cookie.path.should eq "/"

    time = Time.now.utc.round + 60
    expires = time.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; expires=#{expires}; path=/"
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    cookie.should be_an_instance_of WebAgent::Cookie
    cookie.name.should eq "inkid"
    cookie.value.should eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    cookie.expires.should eq time
    cookie.path.should eq "/"
  end

  it 'find_cookie' do
    str = "xmen=off,0,0,1; path=/; domain=.excite2.co.jp; expires=Wednesday, 31-Dec-2037 12:00:00 GMT"
    @cm.parse(str, urify("http://www.excite2.co.jp/"))

    str = "xmen=off,0,0,2; path=/; domain=.excite.co.jp; expires=Wednesday, 31-Dec-2037 12:00:00 GMT"
    @cm.parse(str, urify("http://www.excite.co.jp/"))

    @cm.cookies[0].use = true
    @cm.cookies[1].use = true

    url = urify('http://www.excite.co.jp/hoge/funi/')
    cookie_str = @cm.find(url)
    cookie_str.should eq "xmen=off,0,0,2"
  end

  it 'load_cookies' do
    begin
      File.open("tmp_test.tmp","w") {|f|
	f.write <<EOF
http://www.zdnet.co.jp/news/0106/08/e_gibson.html	NGUserID	d29b8f49-10875-992421294-1	2145801600	www.zdnet.co.jp	/	9	0
http://www.zdnet.co.jp/news/0106/08/e_gibson.html	PACK	zd3-992421294-7436	1293839999	.zdnet.co.jp	/	13	0
http://example.org/	key	value	0	.example.org	/	13	0
http://example.org/	key	value		.example.org	/	13	0
EOF
      }

      @cm.cookies_file = 'tmp_test.tmp'
      @cm.load_cookies()
      c0, c1, c2, c3 = @cm.cookies
      c0.url.to_s.should eq 'http://www.zdnet.co.jp/news/0106/08/e_gibson.html'
      c0.name.should eq 'NGUserID'
      c0.value.should eq 'd29b8f49-10875-992421294-1'
      c0.expires.should eq Time.at(2145801600)
      c0.domain.should eq 'www.zdnet.co.jp'
      c0.path.should eq '/'
      c0.flag.should eq 9

      c1.url.to_s.should eq 'http://www.zdnet.co.jp/news/0106/08/e_gibson.html'
      c1.name.should eq 'PACK'
      c1.value.should eq 'zd3-992421294-7436'
      c1.expires.should eq Time.at(1293839999)
      c1.domain.should eq '.zdnet.co.jp'
      c1.path.should eq '/'
      c1.flag.should eq 13
      #
      c2.expires.should be_nil
      c3.expires.should be_nil
    ensure
      File.unlink("tmp_test.tmp")
    end
  end

  it 'save_cookies' do
    str = <<EOF
http://www.zdnet.co.jp/news/0106/08/e_gibson.html	NGUserID	d29b8f49-10875-992421294-1	2145801600	www.zdnet.co.jp	/	9
http://www.zdnet.co.jp/news/0106/08/e_gibson.html	PACK	zd3-992421294-7436	2145801600	.zdnet.co.jp	/	13
EOF
    begin
      File.open("tmp_test.tmp","w") {|f|
	f.write str
      }
      @cm.cookies_file = 'tmp_test.tmp'
      @cm.load_cookies()
      @cm.instance_eval{@is_saved = false}
      @cm.cookies_file = 'tmp_test2.tmp'
      @cm.save_cookies()
      str2 = ''
      File.open("tmp_test2.tmp","r") {|f|
	str2 = f.read()
      }
      str.should eq str2
      #
      File.exist?('tmp_test2.tmp').should be_true
      File.unlink("tmp_test2.tmp")
      @cm.save_cookies()
      File.exist?('tmp_test2.tmp').should be_false
      @cm.save_cookies(true)
      File.exist?('tmp_test2.tmp').should be_true
    ensure
      File.unlink("tmp_test.tmp")
      if FileTest.exist?("tmp_test2.tmp")
	File.unlink("tmp_test2.tmp")
      end
    end
  end

  it 'not saved expired cookies' do
    begin
      @cm.cookies_file = 'tmp_test.tmp'
      uri = urify('http://www.example.org')
      @cm.parse("foo=1; path=/", uri)
      @cm.parse("bar=2; path=/; expires=", uri)
      @cm.parse("baz=3; path=/; expires=\"\"", uri)
      @cm.parse("qux=4; path=/; expires=#{(Time.now + 10).asctime}", uri)
      @cm.parse("quxx=5; path=/; expires=#{(Time.now - 10).asctime}", uri)
      @cm.save_cookies()
      @cm.load_cookies
      @cm.cookies.size.should eq 1
    ensure
      File.unlink("tmp_test.tmp") if File.exist?("tmp_test.tmp")
    end
  end

  it 'add' do
    c = WebAgent::Cookie.new()
    c.name = "hoge"
    c.value = "funi"
    c.url = urify("http://www.inac.co.jp/hoge")
    @cm.add(c)
    c = @cm.cookies[0]
    c.name.should eq 'hoge'
    c.value.should eq 'funi'
    c.expires.should be_nil
  end

  it 'add2' do
    c = WebAgent::Cookie.new()
    c.name = "hoge"
    c.value = "funi"
    c.path = ''
    c.url = urify("http://www.inac.co.jp/hoge/hoge2/hoge3")
    @cm.add(c)
    #
    c = WebAgent::Cookie.new()
    c.name = "hoge"
    c.value = "funi"
    #c.path = '' NO path given -> same as URL
    c.url = urify("http://www.inac.co.jp/hoge/hoge2/hoge3")
    @cm.add(c)
    #
    c1, c2 = @cm.cookies
    c1.path.should eq ''
    c2.path.should eq '/hoge/hoge2'
  end

  it 'test_check_cookie_accept_domain' do
    @cm.accept_domains = [".example1.co.jp", "www1.example.jp"]
    @cm.reject_domains = [".example2.co.jp", "www2.example.jp"]
    check1 = @cm.check_cookie_accept_domain("www.example1.co.jp")
    check1.should be_true
    check2 = @cm.check_cookie_accept_domain("www.example2.co.jp")
    check2.should be_false
    check3 = @cm.check_cookie_accept_domain("www1.example.jp")
    check3.should be_true
    check4 = @cm.check_cookie_accept_domain("www2.example.jp")
    check4.should be_false
    check5 = @cm.check_cookie_accept_domain("aa.www2.example.jp")
    check5.should be_true
    check6 = @cm.check_cookie_accept_domain("aa.www2.example.jp")
    check6.should be_true
    @cm.check_cookie_accept_domain(nil).should be_false
  end

end
