
Use the FireEye feed integration to fetch indicators from the FireEye Intelligence Feed feed.

## Configure FireEye Feed on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for FireEye Feed.
3. Click __Add instance__ to create and configure a new integration instance.

    | Parameter | Description |
    | --- | --- |
    | Name | A meaningful name for the integration instance. |
    | Fetch indicators | Whether to fetch indicators, if checked. |
    | Indicator Reputation | The reputation applied to indicators from this integration instance. The default value is "Bad". |
    | Source Reliability | The reliability of the source providing the intelligence data. The default value is "C - Fairly reliable" |
    | Indicator Expiration Method | The method by which to expire indicators from this feed for this integration instance. |
    | Indicator Expiration Interval | How often to expire the indicators from this integration instance (in minutes). This only applies if the `feedExpirationPolicy` is set to "interval". The default value is 20160 (two weeks). |
    | Feed Fetch Interval | How often to fetch indicators from the feed for this integration instance (in minutes). The default value is 60. | 
    | Public Key + Password | The credentials used to access the feed's data. | 
    | Bypass exclusion list | Whether the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. |

4. Click __Test__ to validate the connection.


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get indicators from the feed
---
Gets the feed indicators and reports.

##### Base Command

`!fireeye-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. | Optional | 


##### Context Output

There is no context output for this command.

