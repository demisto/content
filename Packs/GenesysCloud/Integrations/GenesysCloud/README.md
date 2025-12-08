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
Gets audit events from Genesys Cloud from the past 14 days. This command is intended for development and debugging purposes, as it may produce duplicate events, exceed API request rate limits, and disrupt the fetch events mechanism.

#### Base Command

`genesys-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Optional |
| service_name | Filter by alert status. Possible values are: Architect, PeoplePermissions, ContactCenter, Groups, Telephony, Outbound, Routing, Integrations, AnalyticsReporting. | Required |
| limit | Maximum number of audit events to return. | Optional |
| from_date | The start date from which to get events. Must be within the last 14 days. Default value is 1 hour ago. | Optional |
| to_date | The end date till which to get events. Must be within the last 14 days. Default value is now. | Optional |

#### Context Output

There is no context output for this command.

## Limitations

* The `genesis-cloud-get-events` is only able to retrieve events from the past 14 days. Ensure both the `from_date` and `to_date` command arguments are within the last 14 days.
