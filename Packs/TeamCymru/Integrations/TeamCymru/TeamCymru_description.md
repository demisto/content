## Team Cymru Help

Use the Team Cymru integration to get enriched data for IP addresses.


### Configuration Options
- **Proxy URL**: Specify a proxy to be used. The URL should in the format: scheme://host:port. If the scheme is omitted, the default socks5h scheme will be used. To use the system HTTP proxy, you can also specify the value: **system_http**. The following schemes are supported:
  * **socks5h**: SOCKS version 5 protocol with remote DNS resolving.
  * **socks5**: SOCKS version 5 protocol with local DNS resolving.
  * **socks4a**: SOCKS version 4 with remote DNS resolving.
  * **socks4**: SOCKS version 4 with remote local DNS resolving.
  * **http**: HTTP proxy with support for CONNECT method on port 43 (default Whois port). Note that most HTTP proxies block the CONNECT method to non-HTTP/HTTPS standard ports (such as the default Whois port 43).


