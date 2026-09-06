Darkmon TIP indicator feed for Cortex XSOAR. Pulls IPs, URLs, domains, file hashes, emails, and accounts from the Darkmon Threat Intel firehose into the Cortex XSOAR Threat Intelligence Module (TIM). Pair with the Darkmon integration for incident fetching and automation commands.

## Configure Darkmon Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Base URL | Override the Darkmon TIP API base URL only if your tenant points at a non-default endpoint. The default value already targets the production Darkmon TIP service. Leave blank to use the default. | False |
| API key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Tags | Supports CSV values. | False |
| Indicator fetch limit | Maximum number of indicators to fetch per cycle. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### darkmon-get-indicators

***
Fetch a page of Darkmon indicators on demand without waiting for the next scheduled feed cycle. Useful for debugging.

#### Base Command

`darkmon-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of indicators to return. Default is 20. | Optional |

#### Context Output

There is no context output for this command.
