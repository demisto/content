This integration fetches activities, threats, and alerts from SentinelOne.
This integration was integrated and tested with version xx of SentinelOneEventCollector

## Configure SentinelOne Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SentinelOne Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://usea1.sentinelone.net) |  | True |
    | API Token |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch events |  | False |
    | Event types |  | False |
    | First fetch time |  | False |
    | The maximum number of events per fetch should be between 1-1000 | The limit is per event type. For example, if you choose 3 event types \(ACTIVITIES, THREATS, ALERTS\) with a limit of 100, the actually limit will be 300. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sentinelone-get-events
***
Gets events from SentinelOne.


#### Base Command

`sentinelone-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Optional | 
| limit | Maximum number of results to return. Value should be between 1 - 1000. Default is 1000. | Optional | 


#### Context Output

There is no context output for this command.