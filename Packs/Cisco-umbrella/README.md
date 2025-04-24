Using Cisco Umbrella, you can secure your users and apps anywhere they are located. Cisco Umbrella enables you to obtain the information you need to improve and simplify your security management, and provides detection scoring and prediction of emerging threats.

## What does this pack do?

- Get the category, WHOIS data, or security data for a domain.
- Get the DNS database for domains or IP addresses.
- Get a list of malicious domains associated with an IP address.
- Search for domains that match a regex.
- Get the reputation of a domain.
- Get domains associated with registrar email addresses or a nameserver
- Get data for when a domain, IP address, or URL was attributed to a security organization or as a threat type.

This pack also supports execution metrics, as part of the new API Execution Metrics dashboard.


### Rate Limits

The Umbrella Investigate API has four levels of API access:

- **Integration** — Limited to 2000 requests per day.
- **Tier 1**
- **Tier 2**
- **Tier 3**

Depending on your API access tier, the Umbrella Investigate API limits the number of requests for each endpoint. Your organization's API keys share the same rate limit.

#### Commands with Rate Limits:

##### General Commands:
- `!umbrella-get-domain-queryvolume`
- `!umbrella-list-resource-record`
- `!umbrella-domain-related domain`
- `!umbrella-domain-co-occurrences`
- `!umbrella-domain-security`
- `!umbrella-get-ip-bgp`
- `!umbrella-get-asn-bgp`
- `!umbrella-list-domain-subdomain`
- `!umbrella-get-domain-timeline`
- `!umbrella-get-top-most-seen-domain`
- `!umbrella-get-domain-risk-score`

**Rate Limits:**
- **Integration** — 3 requests per second
- **Tier 1** — 3 requests per second
- **Tier 2** — 12 requests per second
- **Tier 3** — 12 requests per second

##### WHOIS-Related Commands:
- `!umbrella-get-domain-whois-history`
- `!umbrella-get-nameserver-whois`
- `!umbrella-get-email-whois`
- `!umbrella-get-whois-for-domain`

**Rate Limits:**
- **Integration** — 3 requests per second
- **Tier 1** — 3 requests per second
- **Tier 2** — 12 requests per second
- **Tier 3** — 48 requests per second

##### Regex WHOIS Command:
- `!umbrella-get-regex-whois`

**Rate Limits (All Tiers):**
- 18 requests per minute

##### Domain Categorization Command:
- `!umbrella-domain-categorization`

**Rate Limits:**
- **Integration** — 3 requests per second
- **Tier 1** — 3 requests per second
- **Tier 2** — 150 requests per second
- **Tier 3** — 150 requests per second

##### Domain Search Commands:
- `!umbrella-domain-search`
- `!domain`

**Rate Limits:**
- Searches prefixed with `.*` characters — 3 requests per minute
- All other searches — 18 requests per minute
