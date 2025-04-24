Github logs event collector integration for Cortex XSIAM.
This integration was integrated and tested with Github REST API V3

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Github Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. 'https://api.github.com/orgs/XXXXX/audit-log') |  | True |
| API Key |  | True |
| Number of incidents to fetch per fetch. |  | False |
| First fetch time interval |  | False |
| The event types to include. | web - returns web \(non-Git\) events, git - returns Git events, all - returns both web and Git events. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### github-get-events
***
Manual command to fetch events and display them.


#### Base Command

`github-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 


#### Context Output

There is no context output for this command.