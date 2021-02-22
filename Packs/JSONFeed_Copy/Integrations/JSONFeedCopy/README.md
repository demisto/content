Fetches indicators from a JSON feed.
This integration was integrated and tested with version xx of JSON Feed_copy
## Configure JSON Feed_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for JSON Feed_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | URL |  | True |
    | Auto detect indicator type | If selected, the indicator type will be auto detected for each indicator. | False |
    | Indicator Type | Type of the indicator in the feed. If auto-detect is checked then the value set as Indicator Type will be ignored. | False |
    | Username |  | False |
    | JMESPath Extractor | JMESPath expression for extracting the indicators. You can use http://jmespath.org/ to identify the proper expression. | True |
    | JSON Indicator Attribute | The JSON attribute that holds the indicator value. Default value is 'indicator'. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Tags | Supports CSV values. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### json-get-indicators
***
Gets the feed indicators.


#### Base Command

`json-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. Default is 50. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


