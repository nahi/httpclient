# coding: utf-8
require 'spec_helper'

require 'uri'
require 'httpclient/cookie'

describe 'Cookies' do
  before :each do
    @c = WebAgent::Cookie.new()
  end

  it { expect(@c).to be_an_instance_of WebAgent::Cookie }

  it '#discard' do
    expect(!!@c.discard?).to be_falsey
    @c.discard = true
    expect(!!@c.discard?).to be_truthy
  end

  it '#match?' do
    url = urify('http://www.rubycolor.org/hoge/funi/#919191')

    @c.domain = 'www.rubycolor.org'
    expect(@c.match?(url)).to be_truthy

    @c.domain = '.rubycolor.org'
    expect(@c.match?(url)).to be_truthy

    @c.domain = 'aaa.www.rubycolor.org'
    expect(@c.match?(url)).to be_falsey

    @c.domain = 'aaa.www.rubycolor.org'
    expect(@c.match?(url)).to be_falsey

    @c.domain = 'www.rubycolor.org'
    @c.path = '/'
    expect(@c.match?(url)).to be_truthy

    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    expect(@c.match?(url)).to be_truthy

    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge/hoge'
    expect(@c.match?(url)).to be_falsey

    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    @c.secure = true
    expect(@c.match?(url)).to be_falsey

    url2 = urify('https://www.rubycolor.org/hoge/funi/#919191')
    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    @c.secure = true
    expect(@c.match?(url2)).to be_truthy

    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    @c.secure = nil
    expect(@c.match?(url2)).to be_truthy

    url.port = 80
    @c.domain = 'www.rubycolor.org'
    @c.path = '/hoge'
    expect(@c.match?(url)).to be_truthy

    url_nopath = URI.parse('http://www.rubycolor.org')
    @c.domain = 'www.rubycolor.org'
    @c.path = '/'
    expect(@c.match?(url_nopath)).to be_truthy
  end

  it '#head_match?' do
    expect(@c.head_match?("","")).to be_truthy
    expect(@c.head_match?("a","")).to be_falsey
    expect(@c.head_match?("","a")).to be_truthy
    expect(@c.head_match?("abcde","abcde")).to be_truthy
    expect(@c.head_match?("abcde","abcdef")).to be_truthy
    expect(@c.head_match?("abcdef","abcde")).to be_falsey
    expect(@c.head_match?("abcde","bcde")).to be_falsey
    expect(@c.head_match?("bcde","abcde")).to be_falsey
  end

  it 'tail_match?' do
    expect(@c.tail_match?("","")).to be_truthy
    expect(@c.tail_match?("a","")).to be_falsey
    expect(@c.tail_match?("","a")).to be_truthy
    expect(@c.tail_match?("abcde","abcde")).to be_truthy
    expect(@c.tail_match?("abcde","abcdef")).to be_falsey
    expect(@c.tail_match?("abcdef","abcde")).to be_falsey
    expect(@c.tail_match?("abcde","bcde")).to be_falsey
    expect(@c.tail_match?("bcde","abcde")).to be_truthy
  end


  it 'domain_match' do
    extend WebAgent::CookieUtils
    expect(!!domain_match("hoge.co.jp",".")).to be_truthy
    expect(!!domain_match("192.168.10.1","192.168.10.1")).to be_truthy
    expect(!!domain_match("192.168.10.1","192.168.10.2")).to be_falsey
    expect(!!domain_match("hoge.co.jp",".hoge.co.jp")).to be_truthy
    expect(!!domain_match("www.hoge.co.jp", "www.hoge.co.jp")).to be_truthy
    expect(!!domain_match("www.hoge.co.jp", "www2.hoge.co.jp")).to be_falsey
    expect(!!domain_match("www.hoge.co.jp", ".hoge.co.jp")).to be_truthy
    expect(!!domain_match("www.aa.hoge.co.jp", ".hoge.co.jp")).to be_truthy
    expect(!!domain_match("www.hoge.co.jp", "hoge.co.jp")).to be_falsey
  end

  it 'join_quotedstr' do
    arr1 = ['hoge=funi', 'hoge2=funi2']
    expect(arr1).to eq @c.instance_eval{join_quotedstr(arr1,';')}
    arr2 = ['hoge="fu', 'ni"',  'funi=funi']
    expect(['hoge="fu;ni"','funi=funi']).to eq @c.instance_eval{join_quotedstr(arr2,';')}
    arr3 = ['hoge="funi";hoge2="fu','ni2";hoge3="hoge"',  'funi="funi"']
    expect(['hoge="funi";hoge2="fu,ni2";hoge3="hoge"',  'funi="funi"']).to eq @c.instance_eval{join_quotedstr(arr3,',')}
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
    expect(cookie).to be_an_instance_of WebAgent::Cookie
    expect(cookie.name).to eq "inkid"
    expect(cookie.value).to eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    expect(cookie.expires).to eq Time.gm(2010, 12, 1, 0,0,0)
    expect(cookie.path).to eq "/"
  end

  it 'parse2' do
    str = "xmen=off,0,0,1; path=/; domain=.excite.co.jp; expires=Wednesday, 31-Dec-2037 12:00:00 GMT"
    @cm.parse(str, urify('http://www.excite.co.jp'))
    cookie = @cm.cookies[0]
    expect(cookie).to be_an_instance_of WebAgent::Cookie
    expect(cookie.name).to eq "xmen"
    expect(cookie.value).to eq "off,0,0,1"
    expect(cookie.domain).to eq ".excite.co.jp"
    expect(cookie.expires).to eq Time.gm(2037,12,31,12,0,0)
    expect(cookie.path).to eq "/"

    expect(cookie.secure?).to be_falsey
    expect(cookie.http_only?).to be_falsey
  end

  it 'parse3' do
    str = "xmen=off,0,0,1; path=/; domain=.excite.co.jp; expires=Wednesday, 31-Dec-2037 12:00:00 GMT;Secure;HTTPOnly"
    @cm.parse(str, urify('http://www.excite.co.jp'))
    cookie = @cm.cookies[0]
    expect(cookie).to be_an_instance_of WebAgent::Cookie
    expect(cookie.name).to eq "xmen"
    expect(cookie.value).to eq "off,0,0,1"
    expect(cookie.domain).to eq ".excite.co.jp"
    expect(cookie.expires).to eq Time.gm(2037,12,31,12,0,0)
    expect(cookie.path).to eq "/"
    expect(cookie.secure?).to be_truthy
    expect(cookie.http_only?).to be_truthy
  end

  it 'parse_double_semicolon' do
    str = "xmen=off,0,0,1;; path=\"/;;\"; domain=.excite.co.jp; expires=Wednesday, 31-Dec-2037 12:00:00 GMT"
    @cm.parse(str, urify('http://www.excite.co.jp'))
    cookie = @cm.cookies[0]
    expect(cookie).to be_an_instance_of WebAgent::Cookie
    expect(cookie.name).to eq "xmen"
    expect(cookie.value).to eq "off,0,0,1"
    expect(cookie.domain).to eq ".excite.co.jp"
    expect(cookie.expires).to eq Time.gm(2037,12,31,12,0,0)
    expect(cookie.path).to eq "/;;"
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
    expect(@cm.cookies).to eq [c2,c4]
  end

  it 'parse_expires' do
    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; expires=; path=/"
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    expect(cookie).to be_an_instance_of WebAgent::Cookie
    expect(cookie.name).to eq "inkid"
    expect(cookie.value).to eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    expect(cookie.expires).to be_nil
    expect(cookie.path).to eq "/"

    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; path=/; expires="
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    expect(cookie).to be_an_instance_of WebAgent::Cookie
    expect(cookie.name).to eq "inkid"
    expect(cookie.value).to eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    expect(cookie.expires).to be_nil
    expect(cookie.path).to eq "/"

    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; path=/; expires=\"\""
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    expect(cookie).to be_an_instance_of WebAgent::Cookie
    expect(cookie.name).to eq "inkid"
    expect(cookie.value).to eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    expect(cookie.expires).to be_nil
    expect(cookie.path).to eq "/"
  end

  it 'parse_after_expiration' do
    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; expires=Wed, 01-Dec-2010 00:00:00 GMT; path=/"
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    expect(cookie).to be_an_instance_of WebAgent::Cookie
    expect(cookie.name).to eq "inkid"
    expect(cookie.value).to eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    expect(cookie.expires).to eq Time.gm(2010, 12, 1, 0,0,0)
    expect(cookie.path).to eq "/"

    time = Time.now.utc.round + 60
    expires = time.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
    str = "inkid=n92b0ADOgACIgUb9lsjHqAAAHu2a; expires=#{expires}; path=/"
    @cm.parse(str, urify('http://www.test.jp'))
    cookie = @cm.cookies[0]
    expect(cookie).to be_an_instance_of WebAgent::Cookie
    expect(cookie.name).to eq "inkid"
    expect(cookie.value).to eq "n92b0ADOgACIgUb9lsjHqAAAHu2a"
    expect(cookie.expires).to eq time
    expect(cookie.path).to eq "/"
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
    expect(cookie_str).to eq "xmen=off,0,0,2"
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
      expect(c0.url.to_s).to eq 'http://www.zdnet.co.jp/news/0106/08/e_gibson.html'
      expect(c0.name).to eq 'NGUserID'
      expect(c0.value).to eq 'd29b8f49-10875-992421294-1'
      expect(c0.expires).to eq Time.at(2145801600)
      expect(c0.domain).to eq 'www.zdnet.co.jp'
      expect(c0.path).to eq '/'
      expect(c0.flag).to eq 9

      expect(c1.url.to_s).to eq 'http://www.zdnet.co.jp/news/0106/08/e_gibson.html'
      expect(c1.name).to eq 'PACK'
      expect(c1.value).to eq 'zd3-992421294-7436'
      expect(c1.expires).to eq Time.at(1293839999)
      expect(c1.domain).to eq '.zdnet.co.jp'
      expect(c1.path).to eq '/'
      expect(c1.flag).to eq 13
      #
      expect(c2.expires).to be_nil
      expect(c3.expires).to be_nil
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
      expect(str).to eq str2
      #
      expect(File.exist?('tmp_test2.tmp')).to be_truthy
      File.unlink("tmp_test2.tmp")
      @cm.save_cookies()
      expect(File.exist?('tmp_test2.tmp')).to be_falsey
      @cm.save_cookies(true)
      expect(File.exist?('tmp_test2.tmp')).to be_truthy
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
      expect(@cm.cookies.size).to eq 1
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
    expect(c.name).to eq 'hoge'
    expect(c.value).to eq 'funi'
    expect(c.expires).to be_nil
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
    expect(c1.path).to eq ''
    expect(c2.path).to eq '/hoge/hoge2'
  end

  it 'test_check_cookie_accept_domain' do
    @cm.accept_domains = [".example1.co.jp", "www1.example.jp"]
    @cm.reject_domains = [".example2.co.jp", "www2.example.jp"]
    check1 = @cm.check_cookie_accept_domain("www.example1.co.jp")
    expect(check1).to be_truthy
    check2 = @cm.check_cookie_accept_domain("www.example2.co.jp")
    expect(check2).to be_falsey
    check3 = @cm.check_cookie_accept_domain("www1.example.jp")
    expect(check3).to be_truthy
    check4 = @cm.check_cookie_accept_domain("www2.example.jp")
    expect(check4).to be_falsey
    check5 = @cm.check_cookie_accept_domain("aa.www2.example.jp")
    expect(check5).to be_truthy
    check6 = @cm.check_cookie_accept_domain("aa.www2.example.jp")
    expect(check6).to be_truthy
    expect(@cm.check_cookie_accept_domain(nil)).to be_falsey
  end

end
