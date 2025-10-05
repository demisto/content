Unit 42 Feed integration provides threat intelligence from Palo Alto Networks Unit 42 research team.
This integration was integrated and tested with version xx of Unit 42 Feed.

## Configure Unit 42 Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | True |
| Feed Types |  | True |
| Indicator Types | Comma-separated list of indicator types to fetch \(File, IP, URL, Domain\). If not specified, all indicator types are fetched. | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Tags | Comma separated list of tags to add to the fetched indicators | False |
| Traffic Light Protocol Color (TLP). Indicator's TLP will override default value. |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | True |
| Indicator Expiration Method |  | True |
| Indicator Expiration Interval |  | False |
| Create relationships |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

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
| indicator_types | Comma-separated list of indicator types to fetch (File, IP, URL, Domain). If not specified, all indicator types are fetched. Possible values are: File, IP, URL, Domain. | Optional |
| limit | The maximum number of indicators to return. The default is 10. Default is 10. | Optional |

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
| limit | The maximum number of threat objects to return. The default is 10. Default is 10. | Optional |

#### Context Output

There is no context output for this command.
