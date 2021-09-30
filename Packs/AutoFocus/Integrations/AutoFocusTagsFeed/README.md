This is the Feed Hello World integration for getting started with your feed integration.
This integration was integrated and tested with version xx of AutoFocusTagsFeed

## Configure AutoFocusTagsFeed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AutoFocusTagsFeed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
    | Use system proxy settings | Use system proxy settings. | False |
    | None |  | False |
    | None |  | False |
    | Tags | Supports CSV values. | False |
    | API Key |  | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### autofocus-tags-feed-get-indicators
***
Gets indicators from the feed.


#### Base Command

`autofocus-tags-feed-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


