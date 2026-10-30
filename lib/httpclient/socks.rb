# Copyright (c) 2008 Jamis Buck
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the 'Software'), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

require 'socket'
require 'resolv'
require 'ipaddr'

#
# This implementation was borrowed from Net::SSH::Proxy
#
class HTTPClient
  # An Standard SOCKS error.
  class SOCKSError < SocketError; end

  # Used for reporting proxy connection errors.
  class SOCKSConnectError < SOCKSError; end

  # Used when the server doesn't recognize the user's credentials.
  class SOCKSUnauthorizedError < SOCKSError; end

  # An implementation of a SOCKS4 proxy.
  class SOCKS4Socket
    # The SOCKS protocol version used by this class
    VERSION = 4

    # The packet type for connection requests
    CONNECT = 1

    # The status code for a successful connection
    GRANTED = 90

    # The proxy's host name or IP address, as given to the constructor.
    attr_reader :proxy_host

    # The proxy's port number.
    attr_reader :proxy_port

    # The additional options that were given to the proxy's constructor.
    attr_reader :options

    # Create a new proxy connection to the given proxy host and port.
    # Optionally, a :user key may be given to identify the username
    # with which to authenticate.
    def initialize(proxy_host, proxy_port = 1080, options = {})
      @proxy_host = proxy_host
      @proxy_port = proxy_port
      @options = options
    end

    # Return a new socket connected to the given host and port via the
    # proxy that was requested when the socket factory was instantiated.
    def open(host, port, connection_options)
      socket = Socket.tcp(proxy_host, proxy_port, nil, nil,
                          connect_timeout: connection_options[:timeout])
      ip_addr = IPAddr.new(Resolv.getaddress(host))

      packet = [
        VERSION, CONNECT, port.to_i,
        ip_addr.to_i, options[:user]
      ].pack('CCnNZ*')
      socket.send packet, 0

      _version, status, _port, _ip = socket.recv(8).unpack('CCnN')
      if status != GRANTED
        socket.close
        raise SOCKSConnectError, "error connecting to socks proxy (#{status})"
      end

      socket
    end
  end

  # An implementation of a SOCKS5 proxy.
  class SOCKS5Socket
    # The SOCKS protocol version used by this class
    VERSION = 5

    # The SOCKS authentication type for requests without authentication
    METHOD_NO_AUTH = 0

    # The SOCKS authentication type for requests via username/password
    METHOD_PASSWD = 2

    # The SOCKS authentication type for when there are no supported
    # authentication methods.
    METHOD_NONE = 0xFF

    # The SOCKS packet type for requesting a proxy connection.
    CMD_CONNECT = 1

    # The SOCKS address type for connections via IP address.
    ATYP_IPV4 = 1

    # The SOCKS address type for connections via domain name.
    ATYP_DOMAIN = 3

    # The SOCKS response code for a successful operation.
    SUCCESS = 0

    # The proxy's host name or IP address
    attr_reader :proxy_host

    # The proxy's port number
    attr_reader :proxy_port

    # The map of options given at initialization
    attr_reader :options

    # Create a new proxy connection to the given proxy host and port.
    # Optionally, :user and :password options may be given to
    # identify the username and password with which to authenticate.
    def initialize(proxy_host, proxy_port = 1080, options = {})
      @proxy_host = proxy_host
      @proxy_port = proxy_port
      @options = options
    end

    # Return a new socket connected to the given host and port via the
    # proxy that was requested when the socket factory was instantiated.
    def open(host, port, connection_options)
      socket = Socket.tcp(proxy_host, proxy_port, nil, nil,
                          connect_timeout: connection_options[:timeout])

      methods = [METHOD_NO_AUTH]
      methods << METHOD_PASSWD if options[:user]

      packet = [VERSION, methods.size, *methods].pack('C*')
      socket.send packet, 0

      version, method = socket.recv(2).unpack('CC')
      if version != VERSION
        socket.close
        raise SOCKSError, "invalid SOCKS version (#{version})"
      end

      if method == METHOD_NONE
        socket.close
        raise SOCKSError, 'no supported authorization methods'
      end

      negotiate_password(socket) if method == METHOD_PASSWD

      packet = [VERSION, CMD_CONNECT, 0].pack('C*')

      if host =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/
        packet << [ATYP_IPV4, $1.to_i, $2.to_i, $3.to_i, $4.to_i].pack('C*')
      else
        packet << [ATYP_DOMAIN, host.length, host].pack('CCA*')
      end

      packet << [port].pack('n')
      socket.send packet, 0

      _version, reply, = socket.recv(2).unpack('C*')
      socket.recv(1)
      address_type = socket.recv(1).getbyte(0)
      case address_type
      when 1
        socket.recv(4) # get four bytes for IPv4 address
      when 3
        len = socket.recv(1).getbyte(0)
        _hostname = socket.recv(len)
      when 4
        _ipv6addr _hostname = socket.recv(16)
      else
        socket.close
        raise SOCKSConnectError, 'Illegal response type'
      end
      _portnum = socket.recv(2)

      unless reply == SUCCESS
        socket.close
        raise SOCKSConnectError, reply.to_s
      end

      socket
    end

    private

    # Simple username/password negotiation with the SOCKS5 server.
    def negotiate_password(socket)
      packet = [
        0x01, options[:user].length, options[:user],
        options[:password].length, options[:password]
      ].pack('CCA*CA*')
      socket.send packet, 0

      _version, status = socket.recv(2).unpack('CC')

      return if status == SUCCESS
      socket.close
      raise SOCKSUnauthorizedError, 'could not authorize user'
    end
  end
end
