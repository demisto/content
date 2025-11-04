Fetch audit events from Genesys Cloud's suite of products and services.
This integration was integrated and tested with version 2 of the Genesys Cloud Platform API.

## Configure Genesys Cloud in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | False |
| Client ID | True |
| Client Secret | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Fetch Events | False |
| Service names | True |
| Maximum Number of Events Per Service | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### genesis-cloud-get-events

***
Gets events from Hello World.

#### Base Command

`genesis-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| service_name | Filter by alert status. Possible values are: Architect, PeoplePermissions, ContactCenter, Groups, Telephony, Outbound, Routing, Integrations, AnalyticsReporting. | Optional | 
| limit | Maximum number of results to return. | Required | 
| from_date | Date from which to get events. | Optional | 

#### Context Output

There is no context output for this command.
