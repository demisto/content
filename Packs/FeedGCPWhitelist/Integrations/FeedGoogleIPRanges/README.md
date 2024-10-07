Use the Google IP Ranges Feed integration to get GCP and Google global IP ranges

## Configure Google IP Ranges Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| IP Address Ranges | IP Ranges group for the feed to fetch | True |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedTags | Tags | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| Enrichment Excluded | Select this option to exclude the fetched indicators from the enrichment process. | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

#### IP Address Ranges
The IP Address Ranges Parameter determines the group of IP ranges for the feed to fetch:
- All GCP customer global and regional external IP ranges:
  This option will fetch GCP customer global and regional external IP rages from https://www.gstatic.com/ipranges/cloud.json.
  This should be used instead of the GCP Whitelist Feed integration.
- All available Google IP ranges:
  This option will fetch All Google IP ranges from https://www.gstatic.com/ipranges/goog.json.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google_ip_rages-get-indicators
***
Gets indicators from the feed.


##### Base Command

`google-ip-ranges-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!google-ip-ranges-get-indicators limit=2```

##### Context Example
```
{}
```

##### Human Readable Output
### Indicators from GCP Whitelist Feed:
|value|type|
|---|---|
| 52.86.122.241/18 | CIDR |
| 52.15.91.198/18 | CIDR |
