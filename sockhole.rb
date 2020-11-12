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

require "socket"
require "logger"
require "ipaddr"
require "resolv"
require "openssl"

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

# a connection to these ports will make a TLS connection and decrypt data
# before handing it back to the client
TLS_PORTS = [
  443, # https
  993, # imaps
  995, # pop3s
]

BUF_SIZE = 512

VERSION_SOCKS5 = 0x05

METHOD_MIN_REQUEST_LENGTH = 3
METHOD_AUTH_NONE = 0x0

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

class Server
  def self.log(prio, str)
    LOGGER.send(prio, "[server] #{str}")
  end

  def self.run!
    server = TCPServer.new(1080)

    log :info, "listening on :1080"

    while tcpsocket = server.accept do
      Thread.new {
        begin
          Client.new(tcpsocket)
        rescue => e
          log :error, "unhandled #{e.class} exception in client: " <<
            "#{e.message}"
          e.backtrace[0, 4].each{|l| log :error, "  #{l}" }
        end
      }.join
    end
  end
end

class ClientDead < StandardError; end

class Client
  attr_reader :socket, :ip, :remote_socket, :tls_decrypt
  attr_accessor :remote_hostname, :remote_ip, :remote_port

  def initialize(tcpsocket)
    @socket = tcpsocket
    @ip = @socket.peeraddr[2]

    log :info, "new connection"

    if !verify_method
      close
      return
    end

    handle_request
    close
    return

  rescue ClientDead
    close
    return
  end

  def log(prio, str)
    LOGGER.send(prio, "[#{ip}] #{str}")
  end

  def close
    if socket
      log :info, "closing connection"
      socket.close
    end

    if remote_socket
      log :info, "closing remote connection"
      remote_socket.close
    end

    @socket = nil
    @remote_socket = nil
  end

  def fail_close(code)
    write [
      VERSION_SOCKS5,
      code,
      0,
      REQUEST_ATYP_IP,
      0, 0, 0, 0,
      0, 0,
    ].pack("C*")

    close

    return false
  end

  def hex(data)
    data.unpack("C*").map{|c| sprintf("%02x", c) }.join(" ")
  end

  def read(len)
    data = socket.sysread(BUF_SIZE)
    log :debug, "<-C #{hex(data)}"
    return data
  rescue SystemCallError, EOFError => e
    log :error, "read: #{e.message}"
    raise ClientDead
  end

  def write(data)
    log :debug, "->C #{hex(data)}"
    wrote = 0
    while data.bytesize > 0
      log :debug, "#{data.bytesize} byte(s) left to write to client"
      len = socket.syswrite(data[0, BUF_SIZE])
      data = data.byteslice(len .. -1)
      wrote += len
    end
  rescue SystemCallError => e
    log :error, "write: #{e.message}"
    raise ClientDead
  end

  def remote_read(len)
    raise ClientDead if !remote_socket
    data = remote_socket.sysread(BUF_SIZE)
    log :debug, "<-R #{data.inspect}"
    return data
  rescue SystemCallError => e
    log :error, "remote read: #{e.message}"
    raise ClientDead
  rescue EOFError => e
    log :error, "remote EOF"
    raise ClientDead
  end

  def remote_write(data)
    raise ClientDead if !remote_socket
    log :debug, "->R #{hex(data)}"
    wrote = 0
    while data.bytesize > 0
      log :debug, "#{data.bytesize} byte(s) left to write to remote"
      len = remote_socket.syswrite(data[0, BUF_SIZE])
      data = data.byteslice(len .. -1)
      wrote += len
    end
  rescue SystemCallError => e
    log :error, "remote write: #{e.message}"
    raise ClientDead
  end

  def verify_method
    data = ""
    while data.bytesize < METHOD_MIN_REQUEST_LENGTH
      data << read(METHOD_MIN_REQUEST_LENGTH)
    end

    if data[0].ord != VERSION_SOCKS5
      log :error, "unsupported version: #{data[0].inspect}"
      return fail_close(REPLY_FAIL)
    end

    data[1].ord.times do |i|
      case data[2 + i].ord
      when METHOD_AUTH_NONE
        write [ VERSION_SOCKS5, METHOD_AUTH_NONE ].pack("C*")
        return true
      end
    end

    log :error, "no supported auth methods"
    return fail_close(REPLY_FAIL)
  end

  def handle_request
    data = read(BUF_SIZE)

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

    begin
      Timeout.timeout(5) do
        @remote_socket = TCPSocket.new(remote_ip, remote_port)

        if tls_decrypt
          ctx = OpenSSL::SSL::SSLContext.new
          # verification doesn't make sense without a hostname
          if remote_hostname
            ctx.set_params(:verify_mode => OpenSSL::SSL::VERIFY_PEER)
          end

          ssl_socket = OpenSSL::SSL::SSLSocket.new(remote_socket, ctx)
          ssl_socket.hostname = remote_hostname ? remote_hostname : remote_ip
          ssl_socket.sync_close = true
          ssl_socket.connect
          @remote_socket = ssl_socket
        end
      end
    rescue Timeout::Error => e
      log :error, "connection to #{remote_ip}:#{remote_port} failed: " <<
        e.message
      return fail_close(REPLY_TTL_EXPIRED)
    rescue Errno::ECONNREFUSED => e
      log :error, "connection to #{remote_ip}:#{remote_port} failed: " <<
        e.message
      return fail_close(REPLY_CONN_REFUSED)
    rescue OpenSSL::SSL::SSLError => e
      log :error, "TLS failure: #{e.message}"
      return fail_close(REPLY_CONN_REFUSED)
    end

    resp = [ VERSION_SOCKS5, REPLY_SUCCESS, 0, REQUEST_ATYP_IP ]
    resp += IPAddr.new(remote_ip).hton.unpack("C*")
    resp += remote_port.to_s.unpack("n2").map(&:to_i)
    write resp.pack("C*")

    loop do
      log :debug, "selecting"

      r, w, e = IO.select([ socket, remote_socket ])

      r.each do |io|
        case io
        when socket
          log :debug, "need to read from client socket"
          data = read(BUF_SIZE)
          log :debug, "read #{data.bytesize} from client"
          remote_write(data)

        when remote_socket
          log :debug, "need to read from remote socket"
          data = remote_read(BUF_SIZE)
          log :debug, "read #{data.bytesize} from remote: #{data.inspect}"
          write(data)
        end
      end

      if e.any?
        log :error, "select failed, closing"
        return close
      end
    end
  end
end

Server.run!
