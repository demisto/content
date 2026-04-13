# Genesys Cloud

Genesys Cloud is a unified, all-in-one cloud collaboration and contact center platform that provides customer interaction and operational audit event data.

## What does this pack do?

- Rest API integration to fetch audit logs
- XDM Mapping for audit events
- **Supported Events:**
  - ContactCenter
  - Telephony
  - Groups
  - Outbound
  - PeoplePermissions

## Configure Genesys Cloud in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Default value is https://api.mypurecloud.com/. | False |
| Client ID | The unique ID of the Genesys Cloud client. | True |
| Client Secret | The secret key used to authenticate the client. | True |
| Trust any certificate (not secure) | | False |
| Use system proxy settings | | False |
| Fetch Events | | False |
| Service names | Ensure all selected services appear in the [audit service mapping information](https://developer.genesys.cloud/devapps/api-explorer#get-api-v2-audits-query-realtime-servicemapping). Possible values are: Architect, PeoplePermissions, ContactCenter, Groups, Telephony, Outbound, Routing, Integrations, AnalyticsReporting. | False |
| Maximum number of events per service | Default value is 2500. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### genesys-cloud-get-events

***
Retrieves audit events from Genesys Cloud from the past 14 days. This command is intended for development and debugging purposes, as it may produce duplicate events, exceed API request rate limits, and disrupt the fetch events mechanism.

#### Base Command

`genesys-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Optional |
| service_name | Filter by the Genesys Cloud service name. Possible values are: Architect, PeoplePermissions, ContactCenter, Groups, Telephony, Outbound, Routing, Integrations, AnalyticsReporting. | Required |
| limit | Maximum number of audit events to return. | Optional |
| from_date | The start date for retrieving events. Must be within the last 14 days. Default is 1 hour ago. | Optional |
| to_date | The end date for retrieving events. Must be within the last 14 days. Default is now. | Optional |

#### Context Output

There is no context output for this command.

## Limitations

- The `genesys-cloud-get-events` command is only able to retrieve events from the past 14 days. Ensure both the `from_date` and `to_date` command arguments are within the last 14 days.
