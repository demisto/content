Use the Cisco Webex Feed integration to fetch indicators from Webex.

## Configure Cisco Webex Feed v2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Enrichment Excluded | Select this option to exclude the fetched indicators from the enrichment process. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-webex-feed-v2-get-indicators

***
Gets indicators from the feed.

#### Base Command

`cisco-webex-feed-v2-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 30. | Optional |
| indicator_type | The indicator type. Possible values are: CIDR, DOMAIN, Both. Default is Both. | Optional |

#### Context Output

There is no context output for this command.

## Changes from Cisco Webex Feed

This integration replaces **Cisco Webex Feed** (Cisco WebEx Feed) for the Cisco Webex connector. Both can run in parallel during migration.

### Commands

* *webex-get-indicators* was replaced by *cisco-webex-feed-v2-get-indicators*.

## Additional Considerations for this version

* The *Tags* parameter is now split on commas, so each value becomes a separate tag.
