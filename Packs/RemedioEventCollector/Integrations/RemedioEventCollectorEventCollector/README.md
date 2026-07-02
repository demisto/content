Fetches misconfiguration events from Remedio (Gytpol) and ingests them into XSIAM.
This integration was integrated and tested with version xx of RemedioEventCollectorEventCollector.

## Configure Remedio Event Collector in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Key | True |
| Maximum misconfigurations per fetch | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### remedio-get-events

***
Manual command to fetch misconfiguration events and display them.

#### Base Command

`remedio-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to push events to XSIAM, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 
| limit | Maximum number of misconfigurations to return. Default is 100. | Optional | 

#### Context Output

There is no context output for this command.
