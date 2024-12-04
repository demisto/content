Fetches Indicators from Github Repo https://github.com/stamparm/maltrail

## Configure Github Maltrail Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Token | API Token | True |
| Username of the repository owner, for example: github.com/repos/{user}/{repo}/issues |  | True |
| Base URL |  | True |
| The name of the requested repository, for example: github.com/repos/{user}/{repo}/issues |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Feed Fetch Interval |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gh-maltrail-get-indicators

***
Get indicators from the feed.

#### Base Command

`gh-maltrail-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return to the output. Default is 50. | Optional | 

#### Context Output

There is no context output for this command.