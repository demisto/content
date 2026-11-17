## ViewDNS

Use the ViewDNS integration to enrich and pivot on domains, IP addresses, name servers, mail servers, and registrants with DNS, IP, and WHOIS intelligence from [ViewDNS.info](https://viewdns.info/api/).

### Get an API key

1. Sign up for a ViewDNS.info account at [https://viewdns.info/api/](https://viewdns.info/api/).
2. Log in and copy the API key from your account dashboard.
3. Paste the key into the **API Key** field of the integration instance.

The WHOIS and Reverse WHOIS commands require a paid API key.

### API query usage

- Every command consumes one ViewDNS API query, except **viewdns-account-balance** and the instance **Test** button, which are free.
- The generic **domain** and **ip** reputation commands are disabled by default. When you select **Enable reputation commands**, each enriched indicator consumes two API queries. Enable it only if your plan can cover automatic enrichment of every domain and IP address in your incidents.
- Use **viewdns-account-balance** to check the remaining queries.

### Active commands

**viewdns-port-scan**, **viewdns-ping**, and **viewdns-traceroute** make ViewDNS servers connect to the target host. Use them with care and only on hosts you are permitted to probe.