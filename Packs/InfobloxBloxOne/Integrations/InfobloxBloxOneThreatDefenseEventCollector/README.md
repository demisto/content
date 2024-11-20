BloxOne Threat Defense is a hybrid cybersecurity solution that leverages DNS as the first line of defense to detect and block cyber threats.

## Configure Infoblox BloxOne Threat Defense Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Service API Key |  | True |
| First fetch time interval |  | False |
| Max events per fetch | The maximum amount of events to retrieve for each event type \(up to 10000 events\). For more information about event types see the help section. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### bloxone-td-event-collector-get-events

***
Gets events. This command is for debugging purposes.

#### Base Command

`bloxone-td-event-collector-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 
| from | Timestamp indicating when to start fetching events. | Required | 
| to | Timestamp indicating when to stop fetching events. | Required | 
| limit | Maximum number of events to fetch. Default is 1000. | Required | 
| offset | offset of the events. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TestGetEvents | Unknown | The event data. | 