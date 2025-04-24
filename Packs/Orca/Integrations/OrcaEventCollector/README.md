Orca Security event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 0.1.0 of Orca Event Collector

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Orca Event Collector in Cortex


| **Parameter** | **Description**                                                                                                           | **Required** |
|---------------------------------------------------------------------------------------------------------------------------| --- | --- |
| API Token | The API Key to use for connection                                                                                         | True |
| Server URL (for example: https://app.eu.orcasecurity.io/api) | For more information about the different regions and ips in the (link)[https://docs.orcasecurity.io/docs/regions-and-ips] | True |
| First fetch time | First fetch query `<number> <time unit>`, e.g., `7 days`. Default `3 days`)                                            | False |
| The maximum number of events per fetch | The number of events to fetch. Maximum value is 1000                                                                      | False |
| Trust any certificate (not secure) |                                                                                                                           | False |
| Use system proxy settings |                                                                                                                           | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### orca-security-get-events

***
Manual command to fetch events from Orca Security.

#### Base Command

`orca-security-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 

#### Context Output

There is no context output for this command.