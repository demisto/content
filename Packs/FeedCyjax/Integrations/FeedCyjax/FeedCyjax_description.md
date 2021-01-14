## Cyjax Feed Help
The feed allows customers to pull indicators of compromise from cyber incidents (IP addresses, URLs, domains, CVE and file hashes).

## Configuration
1. Enter feed name eg. `Cyjax Feed`
2. API URL `https://api.cyberportal.co`
3. Enter Cyjax API token
4. Set proxy if required by your installation
5. Indicator reputation (the reputation set to the indicators fetched from this feed, default is Suspicious)
6. Source reliability: A - Completely reliable
7. Traffic Light Protocol Color - The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed.
8. Use Cyjax feed TLP (selected by default) - Whether to use TLP set by Cyjax. Will override TLP set above.
9. Set feed tags. (optional)
10. Set Indicator Expiration Method (default is never)
11. Fetch interval (default is to fetch every 1 hour)
12. First fetch time. The time interval for the first fetch (retroactive). Default is 3 days.
13. Test connection.
14. Click done to save.