## Whois

Use the Whois integration to get enriched data for domains and ips.

### Configuration Options
- **Return Errors**: If selected, Whois will return errors for unsupported domains, or domains for which the lookup failed.

**For the domain and whois commands:**
- **Proxy URL**: Specify a proxy to be used. The URL should in the format: scheme://host:port. If the scheme is omitted, the default socks5h scheme will be used. To use the system HTTP proxy, you can also specify the value: **system_http** or sign the **Use system proxy settings**. The following schemes are supported:
  * **socks5h**: SOCKS version 5 protocol with remote DNS resolving.
  * **socks5**: SOCKS version 5 protocol with local DNS resolving.
  * **socks4a**: SOCKS version 4 with remote DNS resolving.
  * **socks4**: SOCKS version 4 with local DNS resolving.
  * **http**: HTTP proxy with support for CONNECT method on port 43 (default Whois port). Note that most HTTP proxies block the CONNECT method to non-HTTP/HTTPS standard ports (such as the default Whois port 43).
- **Use legacy context**: Get the Legacy output of context data for 'whois' and 'domain' commands."
  
**For the IP command:**
- **Use system proxy settings**: Use the system proxy settings for the `ip` command.