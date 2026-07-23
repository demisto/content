Fetches Indicators of Compromise (IOCs) from the ThreatMon IOC platform and ingests them into Cortex as indicators.
This integration was integrated and tested with the ThreatMon IOC API.

## Configure ThreatMon Threat Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The ThreatMon IOC API base URL. | True |
| API Token | The ThreatMon API token used to authenticate against the IOC API. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Data Type to Fetch | The type of IOC data to fetch from ThreatMon. | False |
| Maximum number of indicators per fetch | The maximum number of indicators to fetch in a single run. | False |
| Collection IDs | A comma-separated list of ThreatMon collection IDs to filter the fetch by. Leave empty to fetch from all collections. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. | False |
| Feed Fetch Interval |  | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

## Fetched Indicators

The feed maps the ThreatMon `ioc_type` field to Cortex indicator types as follows.

| **ThreatMon ioc_type** | **Cortex indicator type** |
| --- | --- |
| Contains `ip` | IP |
| Contains `domain` | Domain |
| Contains `url` | URL |
| Contains `file` or `hash` | File |

For IP indicators, the `extracted_ip` field is preferred over `ioc_value`, and any port suffix is stripped, so that `1.2.3.4:8080` is ingested as `1.2.3.4`.

The following indicator fields are populated from the ThreatMon response.

| **Indicator field** | **ThreatMon field** |
| --- | --- |
| description | A summary built from source, confidence level, severity, status, ISP, resolved IPs, categories, tags, timestamp and score |
| tags | `tags`, `categories` and `source`, merged with the `ThreatMon` tag |
| modified | `updated_at`, falling back to `timestamp` and then `created_at` |
| confidence | `confidence_level` |
| threatseverity | `severity` |
| status | `status` |
| isp | `isp` |
| resolvedips | `resolved_ips` |
| geolocation | `geo_location` |
| trafficlightprotocol | The **Traffic Light Protocol Color** parameter |

The feed is incremental. On every run it stores the newest indicator timestamp it has seen, and on subsequent runs it skips indicators that are not newer than that timestamp.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatmon-get-indicators

***
Gets a sample of indicators from the ThreatMon feed. This command is used mainly for testing and debugging, and does not create indicators in the system.

#### Base Command

`threatmon-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 10. | Optional |

#### Context Output

There is no context output for this command.

Indicators are also ingested automatically according to the **Feed Fetch Interval** parameter.

## Troubleshooting

- **Test failed** - Verify the API token and that the **Server URL** is reachable from the Cortex engine.
- **No indicators fetched** - Verify that the configured **Collection IDs** contain data, and that **Data Type to Fetch** is not filtering out the indicators you expect. Because the feed is incremental, a run returns nothing when the API has not published indicators newer than the previous run.
