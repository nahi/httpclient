# coding: utf-8

class ProxyServer < BaseServer
  def initialize
    set_logger
    @server = WEBrick::HTTPProxyServer.new(
      :BindAddress => "localhost",
      :Logger => @logger,
      :Port => 0,
      :AccessLog => []
    )
    start
  end
end