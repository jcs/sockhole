#!/usr/bin/env ruby
#
# sockhole: a SOCKS5 decrypting proxy
# Copyright (c) 2020 joshua stein <jcs@jcs.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

require "eventmachine"
require "socket"
require "logger"
require "ipaddr"
require "resolv"
require "openssl"

# a connection to these ports will make a TLS connection and decrypt data
# before handing it back to the client
TLS_PORTS = [
  443, # https
  993, # imaps
  995, # pop3s
]

LISTEN_PORT = 1080
LISTEN_IP = "0.0.0.0"

LOGGER = Logger.new(STDOUT)
if ARGV[0] == "-d"
  LOGGER.level = Logger::DEBUG
else
  LOGGER.level = Logger::INFO
end
LOGGER.datetime_format = "%Y-%m-%d %H:%M:%S"
LOGGER.formatter = proc do |severity, datetime, progname, msg|
  "[#{datetime}] [#{severity[0]}] #{msg}\n"
end

VERSION_SOCKS5 = 0x05

METHOD_MIN_LENGTH = 3
METHOD_AUTH_NONE = 0x0

REQUEST_MIN_LENGTH = 9
REQUEST_COMMAND_CONNECT = 0x1
REQUEST_ATYP_IP = 0x1
REQUEST_ATYP_HOSTNAME = 0x3
REQUEST_ATYP_IP6 = 0x4

REPLY_SUCCESS = 0x0
REPLY_FAIL = 0x1
REPLY_EPERM = 0x02
REPLY_NET_UNREACHABLE = 0x03
REPLY_HOST_UNREACHABLE = 0x04
REPLY_CONN_REFUSED = 0x05
REPLY_TTL_EXPIRED = 0x06
REPLY_BAD_COMMAND = 0x07
REPLY_BAD_ADDRESS = 0x08

class NilClass
  def empty?
    true
  end
end

class ClientDead < StandardError; end

module EMProxyConnection
  attr_reader :client, :hostname, :connected, :tls, :did_tls_verification

  def initialize(client, hostname, tls)
    @client = client
    @hostname = hostname
    @connected = false
    @tls = tls
    @did_tls_verification = false
  end

  def post_init
    if tls
      start_tls(:verify_peer => true, :cert_chain_file => "/etc/ssl/cert.pem")
    end
  end

  def log(prio, str)
    client.log(prio, str)
  end

  def connection_completed
    @connected = true

    # tls connections will call back once verification completes
    if !tls
      client.send_reply REPLY_SUCCESS
    end
  end

  def ssl_verify_peer(pem)
    if hostname.empty?
      return true
    end

    # we'll get called again for other certs in the chain
    if did_tls_verification
      return true
    end

    log :debug, "verifying TLS hostname #{hostname.inspect}"

    cert = OpenSSL::X509::Certificate.new(pem)
    ret = OpenSSL::SSL.verify_certificate_identity(cert, hostname)

    @did_tls_verification = true

    # XXX: this always seems to fail, even when no OpenSSL error is reported
    if !ret
      log :warn, "TLS verification failed for #{hostname.inspect}, aborting"
      #close_connection
      #return false
    end

    return ret

  rescue => e
    log :warn, "error in ssl_verify_peer: #{e.inspect}"
    return false
  end

  def ssl_handshake_completed
    log :debug, "TLS handshake completed, sending reply"
    client.send_reply REPLY_SUCCESS
  end

  def receive_data(_data)
    client.send_data _data
  end

  def unbind
    if connected
      log :info, "closed remote connection"
      client.close_connection_after_writing
    else
      log :info, "failed connecting to remote"
      client.send_reply REPLY_FAIL
    end
  end
end

module EMSOCKS5Connection
  attr_reader :state, :ip, :data, :remote_connection, :tls_decrypt
  attr_accessor :remote_hostname, :remote_ip, :remote_port

  def initialize
    @state = :INIT
    port, @ip = Socket.unpack_sockaddr_in(get_peername)
  end

  def log(prio, str)
    LOGGER.send(prio, "[#{ip}] #{str}")
  end

  def fail_close(code)
    send_data [
      VERSION_SOCKS5,
      code,
      0,
      REQUEST_ATYP_IP,
      0, 0, 0, 0,
      0, 0,
    ].pack("C*")

    close_connection_after_writing
    @state = :DEAD
  end

  def hex(data)
    data.unpack("C*").map{|c| sprintf("%02x", c) }.join(" ")
  end

  def send_reply(code)
    resp = [ VERSION_SOCKS5, code, 0, REQUEST_ATYP_IP ]
    resp += IPAddr.new(remote_ip).hton.unpack("C*")
    resp += remote_port.to_s.unpack("n2").map(&:to_i)
    send_data resp.pack("C*")

    if code == REPLY_SUCCESS
      @state = :PROXY
      @data = ""
    else
      close_connection_after_writing
      @state = :DEAD
    end
  end

  def receive_data(_data)
    log :debug, "<-C #{_data.inspect} #{hex(_data)}"

    (@data ||= "") << _data

    case state
    when :INIT
      if data.bytesize < METHOD_MIN_LENGTH
        return
      end

      @state = :METHOD
      verify_method

    when :REQUEST
      if data.bytesize < REQUEST_MIN_LENGTH
        return
      end

      handle_request

    when :PROXY
      remote_connection.send_data data
      @data = ""
    end
  end

  def send_data(_data)
    log :debug, "->C #{_data.inspect} #{hex(_data)}"
    super
  end

  def verify_method
    if data[0].ord != VERSION_SOCKS5
      log :error, "unsupported version: #{data[0].inspect}"
      return fail_close(REPLY_FAIL)
    end

    data[1].ord.times do |i|
      case data[2 + i].ord
      when METHOD_AUTH_NONE
        send_data [ VERSION_SOCKS5, METHOD_AUTH_NONE ].pack("C*")
        @state = :REQUEST
        @data = ""
        return
      end
    end

    log :error, "no supported auth methods"
    fail_close(REPLY_FAIL)
  end

  def handle_request
    if data[0].ord != VERSION_SOCKS5
      log :error, "unsupported request version: #{data[0].inspect}"
      return fail_close(REPLY_FAIL)
    end

    if (command = data[1].ord) != REQUEST_COMMAND_CONNECT
      log :error, "unsupported request command: #{data[1].inspect}"
      return fail_close(REPLY_BAD_COMMAND)
    end

    case atype = data[3].ord
    when REQUEST_ATYP_IP
      begin
        tmp_ip = data[4, 4].unpack("C*").join(".")
        self.remote_ip = IPAddr.new(tmp_ip).to_s
      rescue IPAddr::InvalidAddressError => e
        log :error, "bogus IP: #{tmp_ip.inspect}"
        return fail_close(REPLY_BAD_ADDRESS)
      end

      # network order
      self.remote_port = data[8, 2].unpack("n")[0]

    when REQUEST_ATYP_HOSTNAME
      len = data[4].ord
      if data.bytesize - 4 < len
        log :error, "hostname len #{len}, but #{data.bytesize - 4} left"
        return fail_close(REPLY_BAD_ADDRESS)
      end

      self.remote_hostname = data[5, len].unpack("a*")[0]

      # network order
      self.remote_port = data[5 + len, 2].unpack("n")[0]

      names = Resolv.getaddresses(remote_hostname).
        select{|n| IPAddr.new(n).ipv4? }
      if names.length == 0
        log :error, "failed to resolve #{remote_hostname.inspect}"
        return fail_close(REPLY_BAD_ADDRESS)
      end

      self.remote_ip = names.shuffle[0]

      # e.g., curl --preproxy socks5h://1.2.3.4 ...
      if self.remote_ip == self.remote_hostname
        @remote_hostname = nil
      end

    when ADDRESS_TYPE_IP_V6
      log :error, "ipv6 not supported"
      return fail_close(REPLY_BAD_ADDRESS)
    end

    if self.remote_port < 1 || self.remote_port >= 65535
      log :error, "bogus port: #{remote_port.inspect}"
      return fail_close(REPLY_BAD_ADDRESS)
    end

    case command
    when REQUEST_COMMAND_CONNECT
      do_connect
    else
      log :error, "unsupported command #{command.inspect}"
    end
  end

  def do_connect
    if TLS_PORTS.include?(remote_port)
      @tls_decrypt = true
    end

    l = "connecting to " << remote_ip << ":" << remote_port.to_s
    if remote_hostname
      l << " (#{remote_hostname})"
    end
    if tls_decrypt
      l << " (TLS decrypt)"
    end
    log :info, l

    # this will call back with send_reply(REPLY_SUCCESS) once connected
    @remote_connection = EventMachine.connect(remote_ip, remote_port,
      EMProxyConnection, self, remote_hostname, tls_decrypt)
  end

  def unbind
    if remote_connection
      remote_connection.close_connection
    end

    log :info, "closed connection"
  end
end

EM.kqueue = true
EM.run do
  EM.start_server(LISTEN_IP, LISTEN_PORT, EMSOCKS5Connection)
  LOGGER.info "[server] listening on #{LISTEN_IP}:#{LISTEN_PORT}"
end
