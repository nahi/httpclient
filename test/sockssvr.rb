require 'logger'
require 'socket'

TEST_USERNAME = 'admin'.freeze
TEST_PASSWORD = 'admin'.freeze

#
# Generic SOCKS[45] server implementation
#
class SOCKSServer
  attr_reader :port

  # protocol version
  SOCKS_VERSION_4 = 4
  SOCKS_VERSION_5 = 5

  # auth method
  SOCKS_NO_AUTH = 0
  SOCKS_USER_PASS_AUTH = 2

  # auth result
  SOCKS_AUTH_SUCCESS = 1
  SOCKS_AUTH_FAILURE = 2

  # host type
  SOCKS_HOSTTYPE_IPV4 = 1
  SOCKS_HOSTTYPE_DOMAIN = 3

  # command
  SOCKS_COMMAND_CONNECT = 1

  # misc
  SOCKS4_MAX_USERNAME = 255

  class SOCKSProtocolError < StandardError; end

  def initialize(port = 1080)
    @server = TCPServer.new(port)
    addr = @server.addr
    addr.shift
    @port = addr[0]
    @logger = Logger.new(STDERR)
    @logger.level = Logger::WARN
    @protocol_version = nil
  end

  def start
    @logger.info('main thread started!')
    Thread.start do
      loop do
        begin
          Thread.start(@server.accept) do |client_socket|
            @logger.info("client from #{client_socket.peeraddr[2]}")
            begin
              handle_client(client_socket)
            rescue SOCKSProtocolError => e
              @logger.warn(e)
              send_protocol_error_response(client_socket)
            rescue RuntimeError => e1
              @logger.warn(e1)
            rescue Errno::ECONNRESET => e2
              @logger.warn("SOCKSServer: Connection Reset by peer")
            ensure
              client_socket.close
            end
          end
        rescue RuntimeError, IOError => e2 # @server.accept error
          @logger.warn(e2) unless e2.instance_of?(IOError)
          break
        end
      end
    end
  end

  def shutdown
    @server.close unless @server.closed?
    @logger.info('Socks server closed... ')
  end

  private

  def handle_client(client_socket)
    socks_version = parse_protocol_version(client_socket)
    @protocol_version = socks_version

    case @protocol_version
    when SOCKS_VERSION_4 # not socks4a, but socks4
      @logger.debug('entering socks4 protocol mode...')
      session = create_socks4_session(client_socket)
      client_socket.send([0x00, 0x5a].concat([0xFF] * 6).pack('C*'), 0)
      forward_packet(session, client_socket)
    when SOCKS_VERSION_5
      @logger.debug('entering socks5 protocol mode...')
      auth_method = get_auth_method(client_socket)
      client_socket.send([SOCKS_VERSION_5, auth_method].pack('C*'), 0)
      unless auth_method == SOCKS_NO_AUTH
        auth_result = authenticate(client_socket)
        send_auth_response(auth_result, client_socket)
        return unless auth_result == SOCKS_AUTH_SUCCESS
      end

      session = create_socks5_session(client_socket)
      forward_packet(session, client_socket)
    end
  end

  def get_username(socket)
    username = nil
    if @protocol_version == SOCKS_VERSION_4
      username = socket.recv(SOCKS4_MAX_USERNAME).unpack('Z*').join('')
    elsif @protocol_version == SOCKS_VERSION_5
      username_length = socket.recv(1).unpack('C')[0]
      username = socket.recv(username_length)
    end
    @logger.debug("got username -> #{username}")
    username
  end

  def get_password(socket)
    if @protocol_version == SOCKS_VERSION_4
      raise SOCKSProtocolError, 'unsupported field -> password'
    end
    password_length = socket.recv(1).unpack('C')[0]
    password = socket.recv(password_length)
    @logger.debug("got password -> #{password}")
    password
  end

  def parse_protocol_version(socket)
    socks_version = socket.recv(1).unpack('C')[0]
    if socks_version != SOCKS_VERSION_4 && socks_version != SOCKS_VERSION_5
      raise "bad socks protocol version -> #{socks_version}"
    end
    socks_version
  end

  def get_auth_method(socket)
    number_of_methods = socket.recv(1).unpack('C')[0]
    if number_of_methods < 1
      raise SOCKSProtocolError,
            'auth method must be > 0'
    end

    @logger.debug("select auth method from #{number_of_methods} choice")

    choice_methods = []
    number_of_methods.times do
      auth_method = socket.recv(1).unpack('C')[0]
      # auth_method == 0 -> NO AUTH
      # auth_method == 2 -> USERNAME:PASSWORD AUTH
      if [SOCKS_NO_AUTH, SOCKS_USER_PASS_AUTH].include?(auth_method)
        @logger.debug("auth method get success -> #{auth_method}")
        choice_methods.push(auth_method)
      end
    end

    raise SOCKSProtocolError, 'unsupported auth method' if choice_methods.empty?

    case choice_methods.size
    when 1
      @logger.debug("selected auth method -> #{choice_methods[0]}")
      return choice_methods[0]
    when 2
      @logger.debug('selected auth method -> 2')
      return SOCKS_USER_PASS_AUTH
    end
  end

  def authenticate(socket)
    version = socket.recv(1).unpack('C')[0]
    if version != 1
      raise SOCKSProtocolError,
            "invalid auth version -> #{version} must be 1"
    end

    username = get_username(socket)
    password = get_password(socket)

    if username == TEST_USERNAME && password == TEST_PASSWORD
      @logger.debug('socks5 username:password auth -> success')
      return SOCKS_AUTH_SUCCESS
    else
      @logger.debug('socks5 username:password auth -> fail')
      return SOCKS_AUTH_FAILURE
    end
  end

  def send_auth_response(auth_result, socket)
    case auth_result
    when SOCKS_AUTH_SUCCESS
      socket.send([SOCKS_VERSION_5, 0x00].pack('C*'), 0)
    when SOCKS_AUTH_FAILURE
      socket.send([SOCKS_VERSION_5, 0xFF].pack('C*'), 0)
    end
  end

  def create_socks4_session(socket)
    command = get_command(socket)
    port, raw_port = get_port(socket)
    host, raw_host = get_ipv4_host(socket)
    _username = get_username(socket)
    session = {
      address_type: SOCKS_HOSTTYPE_IPV4,
      host: host,
      port: port,
      raw_host: raw_host,
      raw_port: raw_port,
      command: command
    }
    session
  end

  def create_socks5_session(socket)
    validate_protocol_version(socket)

    command = get_command(socket)
    check_reserved_byte(socket)
    session = get_host_and_port(socket)
    session[:command] = command
    session
  end

  def validate_protocol_version(socket)
    version = parse_protocol_version(socket)
    unless @protocol_version == version
      raise SOCKSProtocolError,
            "protoversion mismatch #{@protocol_version} != #{version}"
    end
    version
  end

  def get_command(socket)
    @logger.debug('get connection type')
    command = socket.recv(1).unpack('C')[0]
    @logger.debug("command => #{command}")
    command
  end

  def check_reserved_byte(socket)
    # reserved byte
    reserved_byte = socket.recv(1).unpack('C')[0]
    unless reserved_byte.zero?
      raise SOCKSProtocolError,
            "reserved byte must be zero, but #{reserved_byte}"
    end
    @logger.debug("reserved byte => #{reserved_byte}")
  end

  def get_ipv4_host(socket)
    raw_host = socket.recv(4).unpack('C*')
    host = raw_host.join('.')
    @logger.debug("host => #{host}")
    if host.empty?
      raise SOCKSProtocolError,
            'specified host is invalid!'
    end
    [host, raw_host]
  end

  def get_domain(socket)
    domain_length = socket.recv(1).unpack('C')[0]
    if domain_length < 1
      raise SOCKSProtocolError,
            'domain length is too short!'
    end

    host = socket.recv(domain_length)
    raw_host = host.unpack('C*')
    [host, raw_host]
  end

  def get_port(socket)
    raw_port = socket.recv(2).unpack('C*')
    port = raw_port[0] << 8 | raw_port[1]
    [port, raw_port]
  end

  def get_host_and_port(socket)
    address_type = socket.recv(1).unpack('C')[0]
    @logger.debug("address_type #{address_type}")

    case address_type
    when SOCKS_HOSTTYPE_IPV4
      @logger.debug('hostname type is IPv4')
      host, raw_host = get_ipv4_host(socket)
      port, raw_port = get_port(socket)
    when SOCKS_HOSTTYPE_DOMAIN
      @logger.debug('host type is domain name')
      host, raw_host = get_domain(socket)
      port, raw_port = get_port(socket)
    end

    @logger.debug("host => #{host}")
    @logger.debug("raw host => #{raw_host}")
    @logger.debug("port => #{port}")
    @logger.debug("raw port => #{raw_port}")

    session = {
      address_type: address_type,
      host: host,
      port: port,
      raw_host: raw_host,
      raw_port: raw_port
    }
    session
  end

  def forward_packet(session, client_socket)
    command = session[:command]
    raise 'CONNECT is only implemented' unless command == SOCKS_COMMAND_CONNECT

    client_addr = client_socket.peeraddr[2]

    host = session[:host]
    port = session[:port]

    @logger.debug("client #{client_addr} connecting to #{host}:#{port} ...")

    dest_socket = TCPSocket.open(host, port)
    if dest_socket
      target_addr = dest_socket.peeraddr[2]
      send_socks5_response(client_socket, 0, session) # success

      loop do # main io loop
        readables, _, exceptions = IO.select([client_socket, dest_socket])
        raise exceptions[0] unless exceptions.empty?

        readables.each do |io|
          if io == client_socket
            client_msg = client_socket.recv(4096)
            next if client_msg.length.zero?
            @logger.debug("recvmsg from client => #{client_msg.length} bytes")
            @logger.debug("send to dest #{target_addr} => #{client_msg}")
            dest_socket.sendmsg(client_msg)
          elsif io == dest_socket
            dest_msg = dest_socket.recv(4096)
            next if dest_msg.length.zero?
            @logger.debug("recvmsg from dest => #{dest_msg.length} bytes")
            @logger.debug("send to client #{client_addr} => #{dest_msg}")
            client_socket.sendmsg(dest_msg)
          end
        end
      end
    else
      @logger.error("connecting to #{host}:#{port} fail")
      send_socks5_response(client_socket, 1, session) # error
    end
  end

  def send_protocol_error_response(client_socket)
    if @protocol_version == SOCKS_VERSION_4
      client_socket.send([0x00, 0x5b].concat([0xff] * 6).pack('C*'), 0)
    elsif @protocol_version == SOCKS_VERSION_5
      client_socket.send([SOCKS_VERSION_5, 0xff].pack('C*'), 0)
    end
  end

  def send_socks5_response(socket, code, session)
    return unless @protocol_version == SOCKS_VERSION_5

    host = session[:host]
    address_type = session[:address_type]
    raw_host = session[:raw_host]
    raw_port = session[:raw_port]

    resp = [
      SOCKS_VERSION_5, code, 0x00
    ].push(address_type).push(
      host.length
    ).concat(raw_host).concat(raw_port)
    @logger.debug("resp => #{resp.inspect}")
    socket.send(resp.pack('C*'), 0)
  end
end
