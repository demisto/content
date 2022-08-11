This integration fetches indicators from ThreatConnect.
This integration was integrated and tested with version 3 of ThreatConnect Feed

## Configure ThreatConnect Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ThreatConnect Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL |  | True |
    | Access ID | The API ID key. | True |
    | Secret key | The secrete key for the API. | True |
    | Tags to filter results by | A comma-separated list of tags to filter by. | False |
    | Owners | Comma-separated list of owners to fetch indicators from. | False |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Trust any certificate (not secure) |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Tags | Supports CSV values. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### tc-get-indicators
***
Gets indicators from ThreatConnect.


#### Base Command

`tc-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owners | Comma-separated list of owners to fetch indicators from. (If not specified, will retrieve only indicators owned by account. If you supply this argument, it overwrites the "Owners" parameter.) | Optional | 
| limit | The maximum number of indicators to retrieve. Default is 50. | Optional | 
| offset | The index of the first indicator to fetch. Default is 0. Possible values are: . Default is 0. | Optional | 


#### Context Output

There is no context output for this command.
### tc-get-owners
***
Get available indicators owners.


#### Base Command

`tc-get-owners`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
