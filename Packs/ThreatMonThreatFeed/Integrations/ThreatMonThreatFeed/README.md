Fetches Indicators of Compromise (IOCs) from the ThreatMon TAXII 2.1 server and ingests them into Cortex as indicators.
This integration was integrated and tested with the ThreatMon TAXII 2.1 server.

## Configure ThreatMon Threat Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The ThreatMon IOC server URL. Default: `https://ioc.threatmonit.io`. | True |
| Company Name / API Token | The ThreatMon API token. The company name (username) is optional. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Collections | The ThreatMon TAXII collections to fetch. The collections are not subsets of each other, so keep all of them selected to receive every IOC. | False |
| Additional Collection IDs | Optional comma-separated list of additional TAXII collection IDs to fetch. | False |
| First Fetch Time | How far back to fetch indicators on the first run, for example "7 days", "12 hours" or "2026-10-01". Default: 7 days. | False |
| Look-back Window (minutes) | Each crawl re-reads this many minutes before the previous crawl started, so indicators published late are not missed. Re-read indicators are de-duplicated. Default: 180. | False |
| Maximum pages per fetch | Maximum number of TAXII pages (500 indicators each) read in a single fetch run. If more data is available, the next run continues from the same position. Default: 300. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The TLP designation to apply to indicators. If not set, the TLP marking published by ThreatMon is used. | False |
| Feed Fetch Interval | Recommended: 60 minutes. | False |
| Tags | Supports CSV values. The `ThreatMon` tag is always added. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. | False |

## How the Fetch Works

- Every selected collection is paged with the TAXII 2.1 `next` cursor until the server reports `more: false`, so no page is skipped.
- The crawl position is saved after every page. If a run reaches **Maximum pages per fetch**, the platform timeout, or an error, the next run resumes from the same page. Indicators are only marked as processed after they were sent to Cortex.
- The next crawl starts from the server time at which the previous crawl started, minus the **Look-back Window**. The server time (HTTP `Date` header) is used rather than the object timestamps, because some objects are published with timestamps ahead of real time.
- Indicators read more than once (look-back overlap, or the same IOC published in several collections) are de-duplicated. An IOC that is re-published later is sent again so its *Last Seen By Source* is refreshed.

## Fetched Indicators

The STIX 2.1 indicator pattern is mapped to Cortex indicator types as follows.

| **STIX observable** | **Cortex indicator type** |
| --- | --- |
| `ipv4-addr:value` | IP (CIDR for ranges). A `:port` suffix is removed and stored in the `port` field. |
| `ipv6-addr:value` | IPv6 (IPv6CIDR for ranges) |
| `domain-name:value` | Domain (DomainGlob for `*.` wildcards). Values published as domain names but shaped as an IP (`1.2.3.4` or `1.2.3.4:443`), an IPv6 address, a URL (`scheme://...`) or an Ethereum wallet (`0x` + 40 hex) are ingested as IP, IPv6, URL or Cryptocurrency Address. |
| `url:value` | URL |
| `email-addr:value` | Email |
| `file:hashes.*` | File (the `md5`, `sha1`, `sha256`, `sha512` or `ssdeep` field is also set) |

Unsupported observables are skipped and reported in the integration log.

| **Indicator field** | **STIX field** |
| --- | --- |
| tags | `labels`, merged with the `ThreatMon` tag and the **Tags** parameter |
| description | Collection, labels, indicator types, confidence and validity |
| stixid | `id` |
| firstseenbysource | `created` |
| lastseenbysource | `modified` |
| trafficlightprotocol | The **Traffic Light Protocol Color** parameter, or the TLP marking of the object |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatmon-get-indicators

***
Gets a sample of indicators from a ThreatMon collection. This command is used for testing and debugging. It does not create indicators and does not change the fetch state.

#### Base Command

`threatmon-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return (up to 500). Default is 10. | Optional |
| collection | The collection to sample. Default is All Threat Indicators. | Optional |

#### Context Output

There is no context output for this command.

### threatmon-get-fetch-state

***
Shows the fetch checkpoint of every collection, for troubleshooting.

#### Base Command

`threatmon-get-fetch-state`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.FetchState.Collection | String | The collection name. |
| ThreatMon.FetchState.Fetching Since (added_after) | String | The point in time the current or next crawl of the collection starts from. |
| ThreatMon.FetchState.Crawl In Progress | Boolean | Whether a crawl of the collection is in progress and will continue in the next run. |
| ThreatMon.FetchState.Last Completed Crawl | String | When the last complete crawl of the collection started. |

### threatmon-get-collections

***
Lists the collections published by the ThreatMon TAXII server, and whether the integration fetches them by default.

#### Base Command

`threatmon-get-collections`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatMon.Collection.ID | String | The collection ID. |
| ThreatMon.Collection.Title | String | The collection title. |
| ThreatMon.Collection.Description | String | The collection description. |
| ThreatMon.Collection.Can Read | Boolean | Whether the API token can read the collection. |
| ThreatMon.Collection.Known By Integration | Boolean | Whether the collection is one of the predefined collections of the integration. Unknown collections can be fetched with the Additional Collection IDs parameter. |

### threatmon-reset-fetch-state

***
Resets the fetch state, so the next fetch starts again from the First Fetch Time. Indicators that already exist are updated, not duplicated.

#### Base Command

`threatmon-reset-fetch-state`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

<~PLATFORM>

## License Requirements

The following configuration parameters require one of these licenses: **Cortex XSIAM** or **Agentix**:

- Fetch indicators
- Incremental Feed
- Bypass exclusion list

</~PLATFORM>
