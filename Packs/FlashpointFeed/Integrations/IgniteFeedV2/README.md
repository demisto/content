Flashpoint Ignite Feed V2 Integration allows importing indicators of compromise using the V2 API that provides a more concise, context-rich response structure. It includes sightings of IOCs over time and IOC relationships, providing visibility into an IOC's evolution. The indicators of compromise are ingested into Cortex XSOAR and displayed in the War Room.

This integration was integrated and tested with API v2 of Flashpoint Ignite.

## Fetch Indicators

Fetching the Ignite indicators. The indicators that are created or updated after the provided "First fetch time" will be fetched in the ascending order.

If you are upgrading from a Flashpoint Feed integration, please refer to the [Migration Guide](#migration-guide) for guidance.

## Configure Flashpoint Ignite Feed v2 in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Flashpoint Ignite Feed v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | Server URL to connect to Ignite. | True |
    | API Key | API key used for secure communication with the Ignite platform. | True |
    | Types of the indicators to fetch | Types of the indicators to fetch. If not specified, it fetches all the indicators. Options: IPv4, IPv6, Domain, URL, File, Extracted Config. | False |
    | CIDR Range of an IPv4 or IPv6 indicator | CIDR range to filter IPv4 or IPv6 indicators.<br/><br/>Note: This parameter is applied only if the "Types of the indicators to fetch" is IPv4 or IPv6. | False |
    | Maximum Severity Level of an indicator | Filter indicators by their maximum severity level. If not specified, it fetches all the indicators. Options: Informational, Suspicious, Malicious. | False |
    | Minimum Severity Level of an indicator | Filter indicators by their minimum severity level. If not specified, it fetches all the indicators. Options: Informational, Suspicious, Malicious. | False |
    | MITRE ATTACK IDs of an indicator | Filter indicators by their MITRE ATTACK IDs. | False |
    | Tags of an indicator | Filter indicators by their tags. Must be exact tag matches. | False |
    | Actor Tags of an indicator | Filter indicators by their actor tags. Must be exact tag matches. Inclusion of the actor: prefix is optional. | False |
    | Malware Tags of an indicator | Filter indicators by their malware tags. Must be exact tag matches. Inclusion of the malware: prefix is optional. | False |
    | Source Tags of an indicator | Filter indicators by their source tags. Must be exact tag matches. Inclusion of the source: prefix is optional. | False |
    | First fetch time | Backfill indicators by providing date or relative timestamp. Default is '3 days'.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc. | False |
    | Fetch indicators | Enable to fetch indicators. | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
    | Default Indicator Mapping | When selected, all the incoming indicators will map to the Ignite Indicator. | False |
    | Tags | Provides the tags to be added to the indicators. Supports CSV values. | False |
    | feedIncremental | To indicate to the Cortex XSOAR server that a feed is incremental. Generally feeds that fetch based on a time range. For example, a daily feed which provides new indicators for the last day or a feed which is immutable and provides indicators from a search date onwards. | False |
    | feedExpirationPolicy |  | False |
    | feedExpirationInterval |  | False |
    | Feed Fetch Interval | Interval in minutes to fetch indicators. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Create relationships | Create relationships between indicators as part of Enrichment. | False |
    | Trust any certificate (not secure) | Indicates whether to allow connections without verifying SSL certificate's validity. | False |
    | Use system proxy settings | Indicates whether to use XSOAR's system proxy settings to connect to the API. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### flashpoint-ignite-v2-get-indicators

***
Retrieves indicators from the Ignite V2 API. It displays the content of the fetch-indicators command.

#### Base Command

`flashpoint-ignite-v2-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of result objects to return. Maximum allowed limit is 500. Default is 10. | Optional |
| updated_since | Only retrieve values after the given timestamp. This parameter operates on the timestamp when an IOC was last modified.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc. Default is 3 days. | Optional |
| types | Search by Indicator types. Supports comma separated values. Possible values are: IPv4, IPv6, Domain, URL, File, Extracted Config. | Optional |
| from | Fetch indicators after the given count of indicators. Default is 0. | Optional |
| cidr_range | CIDR range to filter IPv4 or IPv6 indicators.<br/><br/>Note: This parameter is applied only if the "types" is IPv4 or IPv6. | Optional |
| max_severity_level | Filter indicators by their maximum severity level. If not specified, it fetches all the indicators. Possible values are: Informational, Suspicious, Malicious | Optional |
| min_severity_level | Filter indicators by their minimum severity level. If not specified, it fetches all the indicators. Possible values are: Informational, Suspicious, Malicious | Optional |
| mitre_attack_ids | Filter indicators by their MITRE ATTACK IDs. Supports comma-separated values. | Optional |
| tags | Filter indicators by their tags. Must be exact tag matches. Supports comma-separated values. | Optional |
| actor_tags | Filter indicators by their actor tags. Must be exact tag matches. Inclusion of the actor: prefix is optional. Supports comma-separated values. | Optional |
| malware_tags | Filter indicators by their malware tags. Must be exact tag matches. Inclusion of the malware: prefix is optional. Supports comma-separated values. | Optional |
| source_tags | Filter indicators by their source tags. Must be exact tag matches. Inclusion of the source: prefix is optional. Supports comma-separated values. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!flashpoint-ignite-v2-get-indicators limit=2 types=URL updated_since="3 days"```

#### Human Readable Output

>### Indicator(s)
>
>|ID|Indicator Type|Indicator Value|Score|Modified At|Created At|Last Seen At|APT Description|MITRE Attack IDs|Sightings|External References|Total Sightings|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| [dummy-id-1](https://app.example.com/iocs/dummy-id-1) | ipv4 | 0.0.0.1 | malicious | 2026-01-01T00:00:00Z | 2026-01-01T00:00:00Z | 2026-01-01T00:00:00Z | N/A | **-** ***id***: T0001<br> ***name***: Dummy Technique<br> **tactics**:<br>  ***values***: Defense-Evasion<br> ***tactic***: Defense-Evasion<br>**-** ***id***: T0002<br> ***name***: Dummy Discovery<br> **tactics**:<br>  ***values***: Discovery<br> ***tactic***: Discovery | **-** ***id***: dummy-sighting-1<br> ***href***: <https://api.example.com/sightings/dummy-sighting-1><br> ***source***: dummy_source<br> ***sighted_at***: 2026-01-01T00:00:00Z<br> **tags**:<br>  ***values***: malware:dummy-malware, source:dummy_source<br> **related_iocs**:<br>  **-** ***id***: dummy-related-id-1<br>   ***type***: file<br>   ***value***: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd<br>   ***href***: <https://api.example.com/indicators/dummy-related-id-1><br> **mitre_attack_ids**:<br>  **-** ***id***: T0001<br>   ***name***: Dummy Technique<br>   **tactics**:<br>    ***values***: Defense-Evasion<br> ***tactic***: Defense-Evasion<br>  **-** ***id***: T0002<br>   ***name***: Dummy Discovery<br>   **tactics**:<br>    ***values***: Discovery<br> ***tactic***: Discovery<br> ***apt_description***: N/A<br> ***malware_description***: N/A<br> ***description***: Observation: dummy-malware [2026-01-01T00:00:00Z] | **-** ***source_name***: Dummy Source<br> ***url***: <https://dummy.example.com> | 1 |
>| [dummy-id-2](https://app.example.com/iocs/dummy-id-2) | file | eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee | unknown | 2026-01-01T00:00:00Z | 2026-01-01T00:00:00Z | 2026-01-01T00:00:00Z |  |  | **-** ***id***: dummy-sighting-2<br> ***href***: <https://api.example.com/sightings/dummy-sighting-2><br> ***source***: dummy_source<br> ***sighted_at***: 2026-01-01T00:00:00Z<br> **tags**:<br>  ***values***: malware:dummy-malware-2, source:dummy_source<br> ***description***: Observation: dummy-malware-2 [2026-01-01T00:00:00Z] |  | 1 |

## Migration Guide

### Migrated Commands

Some of the previous integration's commands have been migrated to new commands. Below is the table showing the commands that have been migrated to the new ones.

| **Flashpoint Ignite Command** | **Flashpoint Ignite v2 Command** |
| --- | --- |
| flashpoint-ignite-get-indicators | flashpoint-ignite-v2-get-indicators |
