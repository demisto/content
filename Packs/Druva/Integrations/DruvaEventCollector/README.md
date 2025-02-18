This is the Druva event collector integration for Cortex XSIAM.

## Configure Druva Event Collector in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Client ID | True |
| Secret Key | True |
| Trust any certificate (not secure) |  |
| Use system proxy settings |  |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### druva-get-events

***
Gets events from Druva API in one batch (max 500). If tracker is given, only its successive events will be fetched.

#### Base Command

`druva-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create Cortex XSIAM events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 
| tracker | A string received in a previous run, marking the point in time from which we want to fetch. | Optional | 

#### Context Output

There is no context output for this command.