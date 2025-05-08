AdminByRequest is a Privileged Access Management (PAM) solution that enables secure, temporary elevation to local admin rights.
This integration was integrated and tested with version xx of AdminByRequestEventCollector.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Admin By Request in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The API Key allows you to programmatically integrate with the Armis ecosystem. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch events |  | False |
| Event types to fetch |  | True |
| Maximum number of Auditlog per fetch | Maximum number of audit log entries to retrieve per fetch cycle. Applies only if the "Auditlog" event type is enabled for fetching. | False |
| Maximum number of Events per fetch | Maximum number of events entries to retrieve per fetch cycle. Applies only if the "Events" event type is enabled for fetching. | False |
| Maximum number of Requests per fetch | Maximum number of requests entries to retrieve per fetch cycle. Applies only if the "Requests" event type is enabled for fetching. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### admin_by_request_get-events

***
Retrieves a list of entries logs events from the AdminByRequest instance.

#### Base Command

`admin_by_request_get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| event_type | The type of event to fetch. Possible values are: Auditlog, Events, Requests. Default is Auditlog. | Optional | 
| limit | Returns no more than the specified number of events (for entries of type 'Requests' the default value is 5000). | Optional | 
| first_fetch | The UTC date or relative timestamp from where to start fetching incidents. Notice that for event types 'Requests' there is option to set a start date. Supported formats: N days, N weeks, N months, N years, yyyy-mm-dd. | Optional | 

#### Context Output

There is no context output for this command.
