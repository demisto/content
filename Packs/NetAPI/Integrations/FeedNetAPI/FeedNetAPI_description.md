NetAPI publishes free threat intelligence lists under the CC BY 4.0 license. No account or API key is needed.

Choose one list per instance:

- **Compromised domains**: phishing, scam and malware domains. More than half of them come from NetAPI's own detection over the zone files of all registries NetAPI imports: domains delegated to sinkhole nameservers, and domains that share nameservers, IP addresses or a redirect target with confirmed phishing domains. The rest is CERT Polska's phishing list. Each indicator carries its threat type (`cert-polska`, `sinkhole-ns` or `related-phishing`) and, for NetAPI's own detection, the evidence.
- **Compromised domains without sinkholed malware domains**: the same list without the domains on sinkhole nameservers. A request to a sinkholed domain usually means an infected device, so keep them when you hunt for infections and leave them out when you only need a blocklist.
- **Honeypot attacker IPs**: IPv4 addresses that attacked the NetAPI honeypot sensors within the last 48 hours, with the attack types, country and network. Known research scanners are left out.

The lists are rebuilt every hour. An unchanged list is not downloaded again.

More information: https://netapi.com/compromised-urls/ and https://netapi.com/compromised-ips/