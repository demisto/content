Use this integration to fetch security incidents from Forcepoint DLP as Cortex XSIAM events.

## Configure Forcepoint DLP Event Collector in Cortex


| **Parameter**                      | **Required** |
|------------------------------------|--------------|
| Server URL                         | True         |
| API Key                            | True         |
| Maximum number of events per fetch | False        |
| First fetch                        | False        |
| Trust any certificate (not secure) | False        |
| Use system proxy settings          | False        |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### forcepoint-dlp-get-events

***
Gets events from Forcepoint DLP.

#### Base Command

`forcepoint-dlp-get-events`

#### Input

| **Argument Name**  | **Description**                                                                                                                      | **Default** | **Required** |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------|-------------|--------------|
| limit              | The number of events to return.                                                                                                      | 10          | Optional     | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. | false       | Required     | 

#### Context Output

There is no context output for this command.