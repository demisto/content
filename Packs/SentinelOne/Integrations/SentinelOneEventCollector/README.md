This integration fetches activities, threats, and alerts from SentinelOne.
This integration was integrated and tested with API version 2.1 of SentinelOne.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure SentinelOne Activity and Alerts in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://usea1.sentinelone.net) | The URL to use for connection | True |
| API Token | The API Token to use for connection | True |
| Trust any certificate (not secure) | Use SSL secure connection or not. | False |
| Use system proxy settings | Use proxy settings for connection or not. | False |
| Fetch events | Whether to bring events or not. | False |
| Event types | What types of events to bring, Possible values are (activities, threats, alerts) | False |
| First fetch time | First fetch query `<number> <time unit>`, e.g., `7 days`. Default `3 days`) | False |
| The maximum number of events per fetch should be between 1-1000 | The limit is per event type. For example, if you choose 3 event types \(ACTIVITIES, THREATS, ALERTS\) with a limit of 100, the actually limit will be 300. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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