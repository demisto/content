Collects Vectra Detections and Audits into XSIAM Events.
This integration was integrated and tested with version 2.2 of Vectra.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Vectra Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| API Token | The API Token to use for authentication. | True |
| First fetch time |  | False |
| Fetch Limit | Maximum amount of detections to fetch. Audits API does not include a fetch limit therefore this configuration is only relevant to detections. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### vectra-get-events

***
Fetches events (detections and audits) from Vectra.

#### Base Command

`vectra-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. | Required | 

#### Context Output

There is no context output for this command.