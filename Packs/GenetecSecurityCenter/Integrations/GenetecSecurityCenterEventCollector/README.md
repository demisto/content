Security Center is the foundation of our unified security portfolio. It lets you connect your security at your own pace, starting with a single core system. Even if you're only interested in upgrading your video surveillance or access control, taking the next step is easy.

## Configure Armis Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| Username | Username and Password. | True |
| Password |  | True |
| Application ID |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Maximum number of events per fetch | Alerts and activity events. |  |
| Use system proxy settings for external requests | Use this if you wish to use proxy setting for external requests (such as sending events) when running with an engine. |


## Commands
You can execute these commands in the War Room in the CLI in Cortex XSIAM.
### genetec-security-center-get-events
***
Manual command to fetch events and display them.


#### Base Command

`genetec-security-center-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum amount of events to retrieve. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. | Required | 
| start_time | The start time to fetch_from, should be in the format of YYYY-MM-DDTHH:MM:SS (e.g. 2024-02-21T23:00:00). | Optional |


#### Context Output

There is no context output for this command.