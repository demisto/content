Unit 42 Feed integration provides threat intelligence from Palo Alto Networks Unit 42 research team.

## Configure Unit 42 Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators | Select this check box to fetch indicators \(default selected\). |  |
| Feed Types | Choose the requested indicator feeds. Indicators feed and Threat Objects \(actors, malware, campaigns, techniques, etc.\) feed \(default is both\). | False |
| Indicator Types | Comma-separated list of indicator types to fetch \(File, IP, URL, Domain\). If not specified, all indicator types are fetched. Changing the indicator types on an existing instance is not supported; to change them, create a new integration instance. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence context. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color (TLP). | The Traffic Light Protocol \(TLP\) designation applied to indicators fetched from the feed. | False |
|  | The feed's expiration policy. | False |
| Indicator Expiration Interval | The indicator's expiration policy. | False |
| Create relationships | Create relationships with other indicators. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## How Fetching Works

The integration fetches indicators and threat objects on a single shared limit per fetch. The total number of items fetched in a run is capped at **20,000** (across both threat objects and indicators combined).

Fetch order within a run:

1. **Threat Objects** are fetched first, consuming from the shared limit.
2. **Indicators** (all configured indicator types, queried together) are then fetched with whatever quota remains.

### Fetch Frequency

- **Indicators** are fetched every hour.
- **Threat Objects** are fetched at most once every 24 hours. If a threat objects fetch is interrupted (more data is available than the limit allows), it resumes on the next run without waiting for the 24-hour window, until it completes.

### Incremental Fetch

When the total limit is reached during a run and more data is still available, the integration saves its position and resumes from where it stopped on the next run, instead of restarting the same query. This ensures no data is skipped across runs.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### unit42-get-indicators

***
Gets indicators from the feed.

#### Base Command

`unit42-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_types | Comma-separated list of indicator types to fetch (File, IP, URL, Domain). If not specified, all indicator types are fetched. Possible values are: File, IP, URL, Domain. Default is File,IP,URL,Domain. | Optional |
| limit | The maximum number of indicators to return. The default is 10. The maximum is 5000. Default is 10. | Optional |

#### Context Output

There is no context output for this command.

### unit42-get-threat-objects

***
Gets threat objects from the feed.

#### Base Command

`unit42-get-threat-objects`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of threat objects to return. The default is 10. The maximum is 5000. Default is 10. | Optional |

#### Context Output

There is no context output for this command.

## Troubleshooting

- *HTTP 403 Forbidden* error when fetching indicators behind a corporate proxy or firewall.
  - This occurs when the proxy or firewall blocks outbound requests to the Unit 42 Feed API endpoint (`prod-us.tas.crtx.paloaltonetworks.com`), which is not listed in the standard Cortex XSOAR System Requirements documentation.
  - **Resolution**: Add `prod-us.tas.crtx.paloaltonetworks.com` (or the wildcard `*.tas.crtx.paloaltonetworks.com`) to your proxy or firewall allowlist. The integration requires outbound HTTPS (port 443) access to the following endpoints:
    - `https://prod-us.tas.crtx.paloaltonetworks.com/api/v1/feeds/indicators`
    - `https://prod-us.tas.crtx.paloaltonetworks.com/api/v1/feeds/threat_objects`
