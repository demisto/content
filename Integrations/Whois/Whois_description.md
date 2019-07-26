## Whois

Provides data enrichment for domains.

### Configuration Options
- **Return Errors**: If checked whois will return errors for unsupported domains or domains that their lookup failed.
- **Proxy URL**: Specify a proxy to be used. URL should be of the form: scheme://host:port. If scheme is left out the default scheme of socks5h will be used. It is also possible to specify the value: **system_http** and then the system http proxy will be used. Supported schemes:
  * **socks5h**: SOCKS version 5 protocol with remote dns resolving.
  * **socks5**: SOCKS version 5 protocol with local dns resolving.
  * **socks4a**: SOCKS version 4 with remote dns resolving.
  * **socks4**: SOCKS version 4 with remote local dns resolving.
  * **http**: HTTP proxy with support for CONNECT method on port 43 (default whois port). Note that most http proxies block the CONNECT method to non http/https standard ports (such as the whois port of 43).

