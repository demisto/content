Mandiant Feed

## Configure FeedMandiant on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FeedMandiant.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
    | Feed Fetch Interval |  | False |
    | Public Key |  | True |
    | Secret Key |  | True |
    | Mandiant indicator type | The type of indicators to fetch. Indicator type might include the following: Domains, IPs, Files and URLs. | False |
    | First fetch time |  | False |
    | Server URL (e.g., https://api.intelligence.fireeye.com) |  | True |
    | X-App-Name | X-App-Name header is required for this API. | True |
    | Maximum number of indicators per fetch |  | False |
    | Tags | Supports CSV values. | False |
    | Timeout | API calls timeout. | False |
    | Trust any certificate (not secure) |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Retrieve indicator metadata | Retrieve additional information for each indicator. Please note that this requires additional API calls. | False |
    | Create Relationships. | Please note that this requires additional API calls. | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### feed-mandiant-get-indicators
***
Get mandiant indicators.


#### Base Command

`feed-mandiant-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of indicators to fetch. | Optional | 
| indicatorMetadata | Retrieve additional data for each indicator. Possible values are: true, false. Default is false. | Optional | 
| indicatorRelationships | Create relationships. Possible values are: true, false. Default is false. | Optional | 
| type | The type of indicators to fetch. Possible values are: Malware, Indicators, Actors. Default is Malware,Indicators,Actors. | Required | 


#### Context Output

There is no context output for this command.
