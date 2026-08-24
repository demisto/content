Real-Time Threat Intelligence Feeds provide data on the different stages of the domain lifecycle: from first-observed in the wild, to newly re-activated after a period of quiet. Newly Active Domains surfaces apex-level domains seen for the first time or after ten or more days of inactivity. Newly Observed Domains surfaces domains that we observe for the first time.

## Configure FeedDomainTools in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Username | API Username and API Key | True |
| API Key |  | True |
| Session ID | The session id to serve as unique identifier. On it's initial use, it will retrieve data from the past 5 days. Defaults to 'dt-cortex-feeds'. | False |
| After | The start of the query window in seconds, relative to the current time, inclusive. Defaults to -3600. | False |
| Top | Limits the number of results in the response payload. Defaults to 5000. | False |
| Feed Type | The DomainTools feed type to fetch. Defaults to 'ALL'. | False |
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

### domaintools-get-indicators

***
Gets indicators from the feed.

#### Base Command

`domaintools-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_type | The DomainTools integration feed type to fetch. Possible values are: nod, nad, noh, domainrdap, domaindiscovery, domainrisk, domainhotlist, iphotlist, iprisk. Default is nod. | Optional |
| session_id | The session id to serve as unique identifier. On it's initial use, it will retrieve data from the past 5 days. Default is dt-cortex-feeds. | Optional |
| domain | The top level domain to query (e.g. `*.com`). | Optional |
| after | The start of the query window in seconds, relative to the current time, inclusive. Defaults to 3600 seconds (1h). Default is -3600. | Optional |
| before | The end of the query window in seconds, relative to the current time, inclusive. | Optional |
| top | Limits the number of results in the response payload. Default is 50. | Optional |
| pdns_resolutions_min | IP Hotlist/IP Risk filter: minimum number of domains seen on this IP in the last 24 hours. | Optional |
| bad_pdns_resolutions_min | IP Hotlist/IP Risk filter: minimum number of confirmed bad domains seen on this IP in the last 24 hours. | Optional |
| total_domains_max | IP Hotlist/IP Risk filter: exclude IPs hosting more than this many total domains (removes superhosters). | Optional |
| third_party_threats_min | IP Hotlist/IP Risk filter: minimum number of domains confirmed with threats on external feeds. | Optional |
| all_threats_combined_percent_min | IP Hotlist/IP Risk filter: minimum percentage of confirmed or predicted malicious domains (0-100). | Optional |
| combined_phishing_percent_min | IP Hotlist/IP Risk filter: minimum combined phishing threat percentage (0-100). | Optional |
| combined_malware_percent_min | IP Hotlist/IP Risk filter: minimum combined malware threat percentage (0-100). | Optional |
| combined_spam_percent_min | IP Hotlist/IP Risk filter: minimum combined spam threat percentage (0-100). | Optional |
| asn | IP Hotlist/IP Risk filter: filter by autonomous system number (digits only). | Optional |
| organization | IP Hotlist/IP Risk filter: exact match organization name filter. | Optional |
| country_code | IP Hotlist/IP Risk filter: two-letter country code to filter by geographic location. | Optional |
| percent_phishing_min | IP Hotlist/IP Risk filter: minimum confirmed phishing percentage (0-100). | Optional |
| percent_malware_min | IP Hotlist/IP Risk filter: minimum confirmed malware percentage (0-100). | Optional |
| percent_spam_min | IP Hotlist/IP Risk filter: minimum confirmed spam percentage (0-100). | Optional |
| all_threats_percent_min | IP Risk filter: minimum percentage threshold for all threat classifications combined (0-100). | Optional |

#### Context Output

There is no context output for this command.
