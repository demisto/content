Unit 42 Feed integration provides threat intelligence from Palo Alto Networks Unit 42 research team.

## Configure Unit 42 Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators | Select this check box to fetch indicators \(default selected\). | True |
| Feed Types | Choose the requested indicator feeds. Indicators feed and Threat Objects \(actors, malware, campaigns, techniques, etc.\) feed \(default is both\). | True |
| Indicator Types | Comma-separated list of indicator types to fetch \(File, IP, URL, Domain\). If not specified, all indicator types are fetched. | False |
| Source Reliability | Reliability of the source providing the intelligence context. | True |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color (TLP). | The Traffic Light Protocol \(TLP\) designation is to apply to indicators fetched from the feed. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | True |
| Feed Expiration Policy | The feed's expiration policy. | True |
| Indicator Expiration Interval | The indicator's expiration policy. | False |
| Create relationships | Create relationships with other indicators. | False |
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
