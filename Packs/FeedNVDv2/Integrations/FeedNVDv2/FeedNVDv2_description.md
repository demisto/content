## NIST NVD CVE FEED
Use this feed to create a feed of CVEs from NIST.

### Rate Limits
NIST firewall rules put in place to prevent denial of service attacks can thwart your application if it exceeds a predetermined rate limit. The public rate limit (without an API key) is 5 requests in a rolling 30 second window; the rate limit with an API key is 50 requests in a rolling 30 second window. Requesting an API key significantly raises the number of requests that can be made in a given time frame. However, it is still recommended that your application sleeps for several seconds between requests so that legitimate requests are not denied, and all requests are responded to in sequence.

### API Key
The feed does not require an API key but having one greatly increases the quota that can be used. The API key can be obtained for 
free from NIST, just follow [this link and its instructions](https://nvd.nist.gov/developers/request-an-api-key).

### Filters
1. **CVSS 3 Severity Filter** - Filters CVEs by their CVSS 3 Score.
2. **Keyword Search** - Uses a keyword (or a sentence) to filter out CVEs by their description. You can test this prior to setup using [NIST website](https://nvd.nist.gov/vuln/search).
3. **KEV Only** - Returns the CVE that appears in CISA's [Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/feed-nv-dv2)