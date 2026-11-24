NetAPI publishes free threat intelligence lists under the CC BY 4.0 license, with no account or API key.

This pack fetches them as indicators:

- **Compromised domains**: phishing, scam and malware domains. More than half of them come from NetAPI's own detection over the zone files of all registries NetAPI imports (domains on sinkhole nameservers, and domains that share infrastructure with confirmed phishing domains). The rest is CERT Polska's phishing list.
- **Compromised domains without sinkholed malware domains**: the same list without the domains on sinkhole nameservers.
- **Honeypot attacker IPs**: IPv4 addresses that attacked the NetAPI honeypot sensors within the last 48 hours.

Each instance fetches one list. Each indicator carries the threat type, the evidence or the attack types, and the first and last seen dates.

For more information, visit <https://netapi.com/compromised-urls/> and <https://netapi.com/compromised-ips/>.
