# ViewDNS

[ViewDNS.info](https://viewdns.info/api/) provides DNS, IP, and WHOIS intelligence covering hundreds of millions of domains. This pack brings that data into Cortex so analysts and playbooks can enrich indicators and pivot across attacker infrastructure during an investigation.

## What does this pack do?

- Finds the domains hosted on the same server as a domain or IP address (reverse IP).
- Finds the domains registered by a person or organization (reverse WHOIS).
- Finds the domains that use a given name server or mail server (reverse NS and reverse MX).
- Retrieves WHOIS records for domains and IP addresses.
- Retrieves the hosting history of a domain and its current DNS records.
- Runs port scan, ping, and traceroute checks against a host from ViewDNS servers.
- Optionally enriches domain and IP indicators through the generic reputation commands.

## Playbooks

- **ViewDNS - Domain Enrichment**: retrieves the WHOIS record, IP history, and DNS records of a domain.
- **ViewDNS - Infrastructure Pivot**: lists the domains co-hosted with an IP address and the domains registered with a registrant email address, with a cap on the number of results.

## Before you start

You need a ViewDNS.info API key. Every lookup consumes API queries from your ViewDNS plan, and WHOIS and reverse WHOIS lookups require a paid API key. See the integration documentation for details on query usage.
