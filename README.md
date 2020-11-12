## sockhole

`sockhole` is a decrypting
[SOCKS](https://en.wikipedia.org/wiki/SOCKS)
proxy.
When it receives a request to make a connection to a port listed in its
`TLS_PORTS` list, it will establish the encrypted connection itself, verify the
TLS certificate, and then proxy decrypted data to the client as if the
connection were made to a plaintext service.

This is intended to support old software/equipment which supports SOCKS proxies
but does not support SSL/TLS or modern ciphers.
That software can establish a plaintext connection over a trusted LAN
connection to a local machine running `sockhole`, and the `sockhole` proxy can
establish a secure tunnel over the public internet.

For example, a computer running a POP3 client with SOCKS proxy support but no
SSL support can connect to a remote POP3 server over TLS just by switching the
port configured in the POP3 client to 995 (POP3S).

### Installation

	server$ bundle install --path vendor/bundle

### Use

	server$ bundle exec ruby sockhole.rb

The `-d` option can be supplied to print debugging information.

### Client Examples

#### Curl

`curl` should be instructed to use the `http` protocol on port 443, not
`https`, or else it will expect encrypted data to come through the SOCKS proxy.
However, when specifying a URL of `http://example.com:443/`, `curl` will send a
header of `Host: example.com:443` which may cause problems on the server end
with it not matching a configured virtual host.
The `-H` option can be used to override the sent `Host` header to remove the
port:

	server$ bundle exec ruby sockhole.rb
	[2020-11-12 08:47:24 -0600] [I] [server] listening on 192.168.1.1:1080

	client$ curl -H "Host: example.com" --preproxy socks5h://192.168.1.1 http://example.com:443/
	<!doctype html>
	...

When connecting to a TLS host with an invalid certificate, `sockhole` will reject
the client before it sends any data.

	client$ curl -H "Host: wrong.host.badssl.com" --preproxy socks5h://192.168.1.1 http://wrong.host.badssl.com:443/
	curl: (97) connection to proxy closed

#### nc

	client$ nc -x 192.168.1.1 imap.fastmail.com imaps
	* OK IMAP4 ready
