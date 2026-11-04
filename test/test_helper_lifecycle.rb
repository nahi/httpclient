require File.expand_path('helper', File.dirname(__FILE__))

class TestSupportLifecycle < Test::Unit::TestCase
  Server = Struct.new(:events, :kind) do
    def shutdown
      events << [kind, :shutdown]
    end
  end

  Listener = Struct.new(:events, :kind) do
    def join
      events << [kind, :join]
    end
  end

  def setup
    @events = []
    @fixture = Object.new.extend(Helper)
    @fixture.setup
  end

  def test_serverport_lazily_starts_server_once
    install_lazy_server(:server, 18_081)

    assert_equal(18_081, @fixture.serverport)
    assert_equal(18_081, @fixture.serverport)
    assert_equal([[:server, :start]], @events)
  end

  def test_proxyport_lazily_starts_proxy_once
    install_lazy_server(:proxyserver, 18_082)

    assert_equal(18_082, @fixture.proxyport)
    assert_equal(18_082, @fixture.proxyport)
    assert_equal([[:proxyserver, :start]], @events)
  end

  def test_teardown_server_joins_listener
    install_server(:server)

    @fixture.teardown_server

    assert_equal([[:server, :shutdown], [:server, :join]], @events)
  end

  def test_teardown_proxyserver_joins_listener
    install_server(:proxyserver)

    @fixture.teardown_proxyserver

    assert_equal([[:proxyserver, :shutdown], [:proxyserver, :join]], @events)
  end

  def test_client_cleanup_error_still_stops_both_servers
    install_server(:server)
    install_server(:proxyserver)
    client = Object.new
    def client.reset_all
      raise IOError, 'client cleanup failed'
    end
    @fixture.instance_variable_set(:@client, client)

    assert_raise(IOError) { @fixture.teardown }
    assert_equal([[:proxyserver, :shutdown], [:proxyserver, :join],
                  [:server, :shutdown], [:server, :join]], @events)
  end

  private

  def install_server(kind)
    @fixture.instance_variable_set("@#{kind}", Server.new(@events, kind))
    @fixture.instance_variable_set("@#{kind}_thread", Listener.new(@events, kind))
  end

  def install_lazy_server(kind, port)
    events = @events
    @fixture.define_singleton_method("setup_#{kind}") do
      events << [kind, :start]
      instance_variable_set("@#{kind}", Server.new(events, kind))
      port_variable = kind == :server ? :@serverport : :@proxyport
      instance_variable_set(port_variable, port)
    end
  end
end
