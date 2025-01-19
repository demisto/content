Collects the events log for authentication and Audit provided by DeCYFIR admin API.
This integration was integrated and tested with version v1 of DeCYFIR Event Collector.

## Configure DeCYFIR Event Collector in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API key | True |
| Number of events to fetch per fetch | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| First fetch time | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### get-decyfir-events

***
Gets events from DeCYFIR.

#### Base Command

`get-decyfir-events`

#### Input

| **Argument Name** | **Description**                                                                                                                   | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------| --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. Value should be between 1 - 500. Default is 100.                                             | Optional | 

#### Context Output

There is no context output for this command.
