Real-Time Threat Intelligence Feeds provide data on the different stages of the domain lifecycle from first-observed in the wild, to newly re-activated after a period of quiet. Newly Active Domains (NAD) Apex-level domains (e.g. `example.com` but not `www.example.com`) that we observe based on the latest lifecycle of the domain. A domain may be seen either for the first time ever, or again after at least 10 days of inactivity (no observed resolutions in DNS). Populated with our global passive DNS (pDNS) sensor network. Newly Observed Domains (NOD) Apex-level domains (e.g. `example.com` but not `www.example.com`) that we observe for the first time, and have not observed previously with our global DNS sensor network.
This integration was integrated and tested with version 1.0.0 of FeedDomainTools.

## Configure FeedDomainTools in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Username | The DomainTools API Username to use. | True |
| API Key | The DomainTools API Key to use. | True |
| Session ID | The session id to serve as unique identifier. On it's initial use, it will retrieve data from the past 5 days. Defaults to 'dt-cortex-feeds'. | False |
| After | The start of the query window in seconds, relative to the current time, inclusive. Defaults to -3600. | False |
| Top | Limits the number of results in the response payload. Defaults to 5000. | False |
| Feed Type | The DomainTools feed type fo fetch. Defaults to 'ALL'. | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Tags | Supports CSV values. |  |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dtfeeds-get-indicators

***
Gets indicators from the feed.

#### Base Command

`dtfeeds-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_type | The DomainTools integration feed type to fetch. Default is nod. | Optional |
| session_id | The session id to serve as unique indentifier. On it's initial use, it will retrieve data from the past 5 days. Default is dt-cortex-feeds. | Optional |
| domain | The top level domain to query (e.g. `*.com`). | Optional |
| after | The start of the query window in seconds, relative to the current time, inclusive. Defaults to 3600 seconds (1h). Default is -3600. | Optional |
| before | The end of the query window in seconds, relative to the current time, inclusive. | Optional |
| top | Limits the number of results in the response payload. Default is 50. | Optional |

#### Context Output

There is no context output for this command.
