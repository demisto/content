Fetches the free NetAPI threat intelligence lists - compromised domains and the IP addresses of attackers seen by the NetAPI honeypot sensors.
The lists are free (CC BY 4.0) and need no account or API key. Configure one instance per list:

- **Compromised domains**: phishing, scam and malware domains. More than half of them come from NetAPI's own detection over the zone files of all registries NetAPI imports: domains delegated to sinkhole nameservers, and domains that share nameservers, IP addresses or a redirect target with confirmed phishing domains. The rest is CERT Polska's phishing list.
- **Compromised domains without sinkholed malware domains**: the same list without the domains on sinkhole nameservers.
- **Honeypot attacker IPs**: IPv4 addresses that attacked the NetAPI honeypot sensors within the last 48 hours.

Domain indicators get the threat type Phishing (`cert-polska`, `related-phishing`) or Malware (`sinkhole-ns`), a description with the NetAPI threat type and the evidence, and the first and last seen dates. IP indicators get every attack type seen (the main one first), the country code, the AS number and owner, and the first and last seen dates. The full CSV row is kept in the raw JSON.

## Configure NetAPI Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| List | The NetAPI list this instance fetches. To fetch more than one list, configure one instance per list. | True |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
|  |  | False |
|  |  | False |
| Feed Fetch Interval | NetAPI rebuilds the lists every hour. Unchanged lists are not downloaded again. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Request Timeout | Timeout of the download request in seconds. The domain list is about 20 MB. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### netapi-get-indicators

***
Gets indicators from the feed.

#### Base Command

`netapi-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return (at most 1000). Default is 50. | Optional | 

#### Context Output

There is no context output for this command.
