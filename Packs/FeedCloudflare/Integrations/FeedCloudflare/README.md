Use the Cloudflare feed integration to fetch indicators from the feed.

## Configure Cloudflare Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cloudflare Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Services |  | True |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Request Timeout | Timeout of the polling request in seconds. | False |
| Tags | Supports CSV values. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cloudflare-get-indicators
***
Gets the feed indicators.


#### Base Command

`cloudflare-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. Default is 50. | Optional | 


#### Context Output

There is no context output for this command.