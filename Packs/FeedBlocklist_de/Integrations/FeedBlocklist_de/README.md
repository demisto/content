Use the Blocklist.de feed integration to fetch indicators from the feed.

## Configure Blocklist.de Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Blocklist.de Feed.
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
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Request Timeout |  | False |
    | Services |  | True |
    | Tags | Supports CSV values. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### blocklist_de-get-indicators
***
Gets the feed indicators.


#### Base Command

`blocklist_de-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. Default is 50. | Optional | 
| indicator_type | The indicator type. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output

### Indicators

>|Value|Type|Rawjson|
>|---|---|---|
>| 1.1.1.1 | IP | value: 1.1.1.1<br>type: IP<br>tags: null |
>| 2.2.2.2 | IP | value: 2.2.2.2<br>type: IP<br>tags: null |
>| 3.3.3.3 | IP | value: 3.3.3.3<br>type: IP<br>tags: null |
