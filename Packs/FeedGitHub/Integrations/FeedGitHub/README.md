This is the Feed GitHub integration for getting started with your feed integration.
This integration was integrated and tested with version 1.0.0 of Github Feed.

## Configure Github Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Base URL | The URL to the GitHub API. | True |
| API Token |  | False |
| Trust any certificate (not secure) |  | False |
| Owner | Username of the repository owner | True |
| Repository / Path to fetch | The name of the repository | True |
| Feed type | Predefined list of indicator types:<br/>- YARA: Parses YARA rules from the feed. The `Yara` pack is required for this type<br/>- STIX: Parses STIX data from the feed.<br/>- IOCs: Parses Indicators of Compromise \(IOCs\) using regex patterns.<br/> | True |
| Branch name | The name of the main branch to which to compare. | True |
| Files extensions to fetch | The extension for the file names to target. | True |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| First fetch time | First commit date of first published indicators to bring. e.g., "1 min ago","2 weeks ago","3 months ago". | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Use system proxy settings |  | False |
| Tags | Insert as a comma-separated list. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### github-get-indicators

***
Gets indicators from the feed within a specified date range and up to a maximum limit..

#### Base Command

`github-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | The start date from which to fetch indicators. Accepts date strings like "7 days ago", "2 weeks ago", etc. Default is 7 days. | Optional | 
| until | The end date until which to fetch indicators. Accepts date strings like "now", "2023-05-19", etc. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 

#### Context Output

There is no context output for this command.