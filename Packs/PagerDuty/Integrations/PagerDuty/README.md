Use the PagerDuty integration to manage schedules and on-call users. 
This integration was integrated and tested with PagerDuty API v2.
## Configure PagerDuty v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PagerDuty v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key | True |
    | Service Key (for triggering events only) | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |
    | Incident type | False |
    | Initial Fetch Interval (In minutes, used only for the first fetch or after Reset last run) | False |

4. Click **Test** to validate the URLs, token, and connection.

## Fetched Incidents Data
By default, the integration will import PagerDuty incidents data as Cortex XSOAR incidents. All incidents created in the minute prior to the configuration of Fetch Incidents and up to current time will be imported.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. [Get all schedules: PagerDuty-get-all-schedules](#pagerduty-get-all-schedules)
2. [Get information for on-call users by time or schedule: PagerDuty-get-users-on-call](#pagerduty-get-users-on-call)
3. [Get information for current on-call users: PagerDuty-get-users-on-call-now](#pagerduty-get-users-on-call-now)
4. [Get incidents: PagerDuty-incidents](#pagerduty-incidents)
5. [Create a new event/incident: PagerDuty-submit-event](#pagerduty-submit-event)
6. [Get the contact methods of a user: PagerDuty-get-contact-methods](#pagerduty-get-contact-methods)
7. [Get a user's notification rules: PagerDuty-get-users-notification](#pagerduty-get-users-notification)
8. [Resolve an event: PagerDuty-resolve-event](#pagerduty-resolve-event)
9. [Acknowledge an event: PagerDuty-acknowledge-event](#pagerduty-acknowledge-event)
10. [Get incident information: PagerDuty-get-incident-data](#pagerduty-get-incident-data)
11. [Get service keys for each configured service: PagerDuty-get-service-keys](#pagerduty-get-service-keys)

### PagerDuty-get-all-schedules
***
Receive all schedules from PagerDuty


#### Base Command

`PagerDuty-get-all-schedules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Show only the schedules whose name matches the query. | Optional | 
| limit | The limit for the amount of schedules to receive(Default is 25, max value is 100). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDuty.Schedules.id | string | The ID of the schedule | 
| PagerDuty.Schedules.name | string | The name of the schedule | 


#### Command Example
```!PagerDuty-get-all-schedules```

#### Context Example
```json
{
    "PagerDuty": {
        "Schedules": [
            {
                "escalation_policies": [
                    {
                        "id": "someid",
                        "name": "Default"
                    }
                ],
                "id": "scheduleid",
                "name": "New Schedule #1",
                "time_zone": "America/Los_Angeles",
                "today": "2021-03-10"
            },
            {
                "escalation_policies": [
                    {
                        "id": "anotherid",
                        "name": "test policy"
                    }
                ],
                "id": "anotherscheduleid",
                "name": "New Schedule #2",
                "time_zone": "Europe/Athens",
                "today": "2021-03-10"
            }
        ]
    }
}
```

#### Human Readable Output

>### All Schedules
>|ID|Name|Today|Time Zone|Escalation Policy|Escalation Policy ID|
>|---|---|---|---|---|---|
>| scheduleid | New Schedule #1 | 2021-03-10 | America/Los_Angeles | Default | someid |
>| anotherscheduleid | New Schedule #2 | 2021-03-10 | Europe/Athens | test policy | anotherid |


### PagerDuty-get-users-on-call
***
Returns the names and details of on call users at a certain time or by specific schedule


#### Base Command

`PagerDuty-get-users-on-call`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scheduleID | (default and mandatory) The unique identifier of the schedule. | Required | 
| since | The start of the date range Using ISO 8601 Representation. E.g. !PagerDutyGetUsersOnCall since=2011-05-06T17:00Z. | Optional | 
| until | The end of the date range. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDutyUser.id | string | User's ID | 
| PagerDutyUser.Emails | string | Email of user | 
| PagerDutyUser.Username | string | Username of person | 
| PagerDutyUser.DisplayName | string | Display name of person | 
| PagerDutyUser.Role | string | Display role of person | 
| PagerDutyUser.TimeZone | string | The time zone of the user | 


#### Command Example
```!PagerDuty-get-users-on-call scheduleID=scheduleid```

#### Context Example
```json
{
    "PagerDutyUser": [
        {
            "DisplayName": "Demisto User",
            "Email": "demisto@demisto.com",
            "ID": "someid",
            "Role": "owner",
            "TimeZone": "Europe/Athens",
            "Username": "Demisto User"
        },
        {
            "DisplayName": "Another User",
            "Email": "demisto@gmail.com",
            "ID": "anotherid",
            "Role": "user",
            "TimeZone": "Europe/Athens",
            "Username": "Another User"
        }
    ]
}
```

#### Human Readable Output

>### Users On Call
>|ID|Email|Name|Role|User Url|Time Zone|
>|---|---|---|---|---|---|
>| someid | demisto@demisto.com | Demisto User | owner | https://demisto.pagerduty.com/users/someid | Europe/Athens |
>| anotherid | demisto@mail.com | Another User | user | https://demisto.pagerduty.com/users/anotherid | Europe/Athens |


### PagerDuty-get-users-on-call-now
***
Returns the names and details of current on call personnel


#### Base Command

`PagerDuty-get-users-on-call-now`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the amount of users to receive(Default is 25, max value is 100). | Optional | 
| escalation_policy_ids | Filters the results, showing only on-call users for the specified escalation policy IDs. | Optional | 
| schedule_ids | Filters the results, showing only on-call users for the specified schedule IDs. If the value is null, permanent on-call user are included due to direct user escalation policy targets. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDutyUser.ID | string | User's ID | 
| PagerDutyUser.Email | string | Email of user | 
| PagerDutyUser.Username | string | Username of person | 
| PagerDutyUser.DisplayName | string | Display name of person | 
| PagerDutyUser.Role | string | Role of person | 
| PagerDutyUser.TimeZone | string | The time zone of the user | 


#### Command Example
```!PagerDuty-get-users-on-call-now```

#### Context Example
```json
{
    "PagerDutyUser": [
        {
            "DisplayName": "Demisto User",
            "Email": "demisto@demisto.com",
            "ID": "someid",
            "Role": "owner",
            "TimeZone": "Europe/Athens",
            "Username": "Demisto User"
        }
    ]
}
```

#### Human Readable Output

>### Users On Call Now
>|ID|Email|Name|Role|User Url|Time Zone|
>|---|---|---|---|---|---|
>| someid | demisto@demisto.com | Demisto User | owner | https://demisto.pagerduty.com/users/someid | Europe/Athens |

### PagerDuty-incidents
***
Shows incidents in PagerDuty. Default status parameters are triggered,acknowledged


#### Base Command

`PagerDuty-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Returns only the incidents currently in the passed status(es). Valid status options are triggered,acknowledged, and resolved. (Default values are triggered,acknowledged). Possible values are: triggered, acknowledged, resolved. | Optional | 
| since | Beginning date and time. Using ISO 8601 Representation. E.g. PagerDutyIncidents since=2011-05-06T17:00Z (must be used with until argument). | Optional | 
| sortBy | Used to specify both the field you wish to sort the results on, as well as the direction (ascending/descending) of the results.See more https://v2.developer.pagerduty.com/v2/page/api-reference#!/Incidents/get_incidents. | Optional | 
| until | Last date and time.  Using ISO 8601 Representation. E.g. PagerDutyIncidents until=2016-05-06T13:00Z. | Optional | 
| incident_key | Incident de-duplication key,. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDuty.Incidents.ID | string | Incident ID | 
| PagerDuty.Incidents.Title | string | The title of the incident | 
| PagerDuty.Incidents.Status | string | Incident Status | 
| PagerDuty.Incidents.created_at | date | Time in which the incident was created | 
| PagerDuty.Incidents.urgency | string | Incident Urgency | 
| PagerDuty.Incidents.assignee | string | The assignee of the incident  | 
| PagerDuty.Incidents.service_id | string | The id of the impacted service | 
| PagerDuty.Incidents.service_name | string | The name of the impacted service | 
| PagerDuty.Incidents.escalation_policy | string | The escalation policy | 
| PagerDuty.Incidents.last_status_change_at | date | Time in which the last status change occurred | 
| PagerDuty.Incidents.last_status_change_by | string | Name of the user who done the last status change | 
| PagerDuty.Incidents.number_of_escalations | number | Number of escalations that took place | 
| PagerDuty.Incidents.resolved_by | string | Name of the User who resolved the incident | 
| PagerDuty.Incidents.resolve_reason | string | The reason for resolving the issue | 
| PagerDuty.Incidents.Description | string | The Description of the incident | 
| PagerDuty.Incidents.teams.ID | string | The ID of the team assigned for the incident. | 
| PagerDuty.Incidents.teams.ID | string | The name of the team assigned for the incident. | 
| PagerDuty.Incidents.assignment.time | date | The time of the assignment to the incident | 
| PagerDuty.Incidents.assignment.assignee | string | The name of the assignee to the incident | 
| PagerDuty.Incidents.assignment.assigneeId | string | The ID of the assignee to the incident | 
| PagerDuty.Incidents.acknowledgement.time | date | The time of the acknowledgement to the incident | 
| PagerDuty.Incidents.acknowledgement.acknowledger | string | The name of the acknowledger to the incident | 
| PagerDuty.Incidents.acknowledgement.acknowledgerId | string | The ID of the acknowledger to the incident | 
| PagerDuty.Incidents.incident_key | String | The incident's de-duplication key | 


#### Command Example
```!PagerDuty-incidents```

#### Context Example
```json
{
    "PagerDuty": {
        "Incidents": [
            {
                "Description": {
                    "description": "No description"
                },
                "ID": "someid",
                "Status": "acknowledged",
                "Title": "[#264] Ticket 01439490",
                "acknowledgement": {
                    "acknowledger": "someone",
                    "acknowledgerId": "ABC123",
                    "time": "2021-03-04T08:53:04Z"
                },
                "assignee": "someone",
                "assignment": {
                    "assignee": "someone",
                    "assigneeId": "ABC123",
                    "time": "2021-03-04T08:53:04Z"
                },
                "created_at": "2021-03-04T08:52:56Z",
                "escalation_policy": "Default",
                "incident_key": null,
                "last_status_change_at": "2021-03-04T08:53:04Z",
                "last_status_change_by": "someone",
                "number_of_escalations": null,
                "resolve_reason": "",
                "resolved_by": "someone",
                "service_id": "P5CX6RZ",
                "service_name": "PD SF",
                "teams": [],
                "urgency": "high"
            },
            {
                "Description": {
                    "description": "No description"
                },
                "ID": "anotherid",
                "Status": "triggered",
                "Title": "[#278] my event",
                "acknowledgement": {},
                "assignee": "someone-else",
                "assignment": {
                    "assignee": "someone-else",
                    "assigneeId": "ABC123",
                    "time": "2021-03-10T08:37:17Z"
                },
                "created_at": "2021-03-10T07:57:16Z",
                "escalation_policy": "Default",
                "incident_key": "somekey",
                "last_status_change_at": "2021-03-10T08:37:17Z",
                "last_status_change_by": "API Service",
                "number_of_escalations": null,
                "resolve_reason": "",
                "resolved_by": "someone-else",
                "service_id": "someid",
                "service_name": "API Service",
                "teams": [],
                "urgency": "high"
            }
        ]
    }
}
```

#### Human Readable Output

>### PagerDuty Incidents
>|ID|Title|Description|Status|Created On|Urgency|Html Url|Incident key|Assigned To User|Service ID|Service Name|Escalation Policy|Last Status Change On|Last Status Change By|Resolved By User|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| someid | [#264] Ticket 01439490 | description: No description | acknowledged | 2021-03-04T08:52:56Z | high | https://demisto.pagerduty.com/incidents/someid |  | someone | P5CX6RZ | PD SF | Default | 2021-03-04T08:53:04Z | someone | - |
>| anotherid | [#278] my event | description: No description | triggered | 2021-03-10T07:57:16Z | high | https://demisto.pagerduty.com/incidents/anotherid | somekey | someone-else | someid | API Service | Default | 2021-03-10T08:37:17Z | API Service | - |

### PagerDuty-submit-event
***
Creates a new event/incident in PagerDuty(In order to use this command you have to enter the Service Key in the integration settings)


#### Base Command

`PagerDuty-submit-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | Specific human-readable unique identifier, such as a hostname, for the system having the problem. | Required | 
| summary | 	 A high-level, text summary message of the event. Will be used to construct an alert's description. | Required | 
| severity | The severity of the event. Possible values are: critical, error, warning, info. | Required | 
| action | The action to be executed. Possible values are: trigger, acknowledge, resolve. | Required | 
| description | A short description of the problem. | Optional | 
| group | A cluster or grouping of sources. For example, sources “prod-datapipe-02” and “prod-datapipe-03” might both be part of “prod-datapipe”. Example: "prod-datapipe" "www". | Optional | 
| event_class | The class/type of the event. Example: "High CPU" "Latency". | Optional | 
| component | The part or component of the affected system that is broken. Example: "keepalive" "webping". | Optional | 
| incident_key | Incident key, used to acknowledge/resolve specific event. | Optional | 
| serviceKey | Service key for the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDuty.Event.Status | string | Status of the action on the event | 
| PagerDuty.Event.incident_key | string | Incident key | 


#### Command Example
```!PagerDuty-submit-event action=trigger severity=info source=demisto summary="my new event"```

#### Human Readable Output
>|Incident key|Message|Status|
>|---|---|---|
>| somekey | Event processed | success |


### PagerDuty-get-contact-methods
***
Get the contact methods of a given user


#### Base Command

`PagerDuty-get-contact-methods`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| UserID | ID of the wanted user . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDuty.Contact_methods.phone | string | The phone number of the user | 
| PagerDuty.Contact_methods.id | string | ID of the contact method | 
| PagerDuty.Contact_methods.type | string | The type of the current contact method | 
| PagerDuty.Contact_methods.email | string | The email of the user | 


#### Command Example
```!PagerDuty-get-contact-methods UserID=someid```

#### Context Example
```json
{
    "PagerDuty": {
        "Contact_methods": [
            {
                "email": "demisto@demisto.com",
                "html_url": null,
                "id": "someotherid",
                "label": "Default",
                "self": "https://api.pagerduty.com/users/someid/contact_methods/someotherid",
                "send_html_email": false,
                "send_short_email": false,
                "summary": "Default",
                "type": "email_contact_method"
            },
            {
                "blacklisted": false,
                "html_url": null,
                "id": "someid",
                "label": "Mobile",
                "phone": "000000",
                "self": "https://api.pagerduty.com/users/someid/contact_methods/someid",
                "summary": "Mobile",
                "type": "phone_contact_method"
            },
            {
                "blacklisted": false,
                "enabled": true,
                "html_url": null,
                "id": "onemoreid",
                "label": "Mobile",
                "phone": "0000000",
                "self": "https://api.pagerduty.com/users/someid/contact_methods/onemoreid",
                "summary": "Mobile",
                "type": "sms_contact_method"
            }
        ]
    }
}
```

#### Human Readable Output

>### Contact Methods
>|ID|Type|Details|
>|---|---|---|
>| someotherid | Email | demisto@demisto.com |
>| someid | Phone | 0000000 |
>| onemoreid | SMS | 000000 |


### PagerDuty-get-users-notification
***
Get the users notification rules


#### Base Command

`PagerDuty-get-users-notification`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| UserID | ID of the wanted user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDuty.Notification_rules.start_delay_in_minutes | string | The delay time for notifying the user | 
| PagerDuty.Notification_rules.urgency | string | The urgency of the notification | 
| PagerDuty.Notification_rules.id | string | The id of the notification rule | 


#### Command Example
```!PagerDuty-get-users-notification UserID=someid```

#### Context Example
```json
{
    "PagerDuty": {
        "Notification_rules": {
            "contact_method": {
                "address": "demisto@demisto.com",
                "html_url": null,
                "id": "someotherid",
                "label": "Default",
                "self": "https://api.pagerduty.com/users/someid/contact_methods/someotherid",
                "send_html_email": false,
                "send_short_email": false,
                "summary": "Default",
                "type": "email_contact_method"
            },
            "html_url": null,
            "id": "someid",
            "self": "https://api.pagerduty.com/users/someid/notification_rules/someid",
            "start_delay_in_minutes": 0,
            "summary": "0 minutes: channel someotherid",
            "type": "assignment_notification_rule",
            "urgency": "high"
        }
    }
}
```

#### Human Readable Output

>### User notification rules
>|ID|Type|Urgency|Notification timeout(minutes)|
>|---|---|---|---|
>| someid | assignment_notification_rule | high | 0 |


### PagerDuty-resolve-event
***
Resolves an existing event in PagerDuty


#### Base Command

`PagerDuty-resolve-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_key | Incident key. | Required | 
| serviceKey | Service key for the integration. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDuty.Event.Status | string | Status of the action on the event | 
| PagerDuty.Event.incident_key | string | Incident key | 


#### Command Example
```!PagerDuty-resolve-event incident_key=somekey serviceKey=servicekey```

#### Context Example
```json
{
    "Event": {
        "ID": "somekey"
    },
    "PagerDuty": {
        "Event": {
            "Message": "Event processed",
            "Status": "success",
            "incident_key": "somekey"
        }
    }
}
```

#### Human Readable Output

>### Resolve Event
>|Incident key|Message|Status|
>|---|---|---|
>| somekey | Event processed | success |


### PagerDuty-acknowledge-event
***
Acknowledges an existing event in PagerDuty


#### Base Command

`PagerDuty-acknowledge-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_key | Incident key. | Required | 
| serviceKey | Service key for the integration. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDuty.Event.Status | string | Status of the action on the event | 
| PagerDuty.Event.incident_key | string | Incident key | 


#### Command Example
```!PagerDuty-acknowledge-event incident_key=somekey serviceKey=servicekey```

#### Context Example
```json
{
    "Event": {
        "ID": "8e42eeb6391a4a2abeda5d12e09bddec"
    },
    "PagerDuty": {
        "Event": {
            "Message": "Event processed",
            "Status": "success",
            "incident_key": "somekey"
        }
    }
}
```

#### Human Readable Output

>### Acknowledge Event
>|Incident key|Message|Status|
>|---|---|---|
>| somekey | Event processed | success |


### PagerDuty-get-incident-data
***
Get data about a incident from PagerDuty


#### Base Command

`PagerDuty-get-incident-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | ID of the incident to get information for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDuty.Incidents.ID | string | Incident ID | 
| PagerDuty.Incidents.Title | string | The title of the incident | 
| PagerDuty.Incidents.Status | string | Incident Status | 
| PagerDuty.Incidents.created_at | date | Time in which the incident was created | 
| PagerDuty.Incidents.urgency | string | Incident Urgency | 
| PagerDuty.Incidents.assignee | string | The assignee of the incident  | 
| PagerDuty.Incidents.service_id | string | The id of the impacted service | 
| PagerDuty.Incidents.service_name | string | The name of the impacted service | 
| PagerDuty.Incidents.escalation_policy | string | The escalation policy | 
| PagerDuty.Incidents.last_status_change_at | date | Time in which the last status change occurred | 
| PagerDuty.Incidents.last_status_change_by | string | Name of the user who done the last status change | 
| PagerDuty.Incidents.number_of_escalations | number | Number of escalations that took place | 
| PagerDuty.Incidents.resolved_by | string | Name of the User who resolved the incident | 
| PagerDuty.Incidents.resolve_reason | string | The reason for resolving the issue | 
| PagerDuty.Incidents.Description | string | The Description of the incident | 
| PagerDuty.Incidents.teams.ID | string | The ID of the team assigned for the incident. | 
| PagerDuty.Incidents.teams.ID | string | The name of the team assigned for the incident. | 
| PagerDuty.Incidents.assignment.time | date | The time of the assignment to the incident | 
| PagerDuty.Incidents.assignment.assignee | string | The name of the assignee to the incident | 
| PagerDuty.Incidents.assignment.assigneeId | string | The ID of the assignee to the incident | 
| PagerDuty.Incidents.acknowledgement.time | date | The time of the acknowledgement to the incident | 
| PagerDuty.Incidents.acknowledgement.acknowledger | string | The name of the acknowledger to the incident | 
| PagerDuty.Incidents.acknowledgement.acknowledgerId     | string | The ID of the acknowledger to the incident |
| PagerDuty.Incidents.incident_key | String | The incident's de-duplication key | 


#### Command Example
```!PagerDuty-get-incident-data incident_id=someid```

#### Context Example
```json
{
    "PagerDuty": {
        "Incidents": {
            "Description": "",
            "ID": "someid",
            "Status": "acknowledged",
            "Title": "[#281] my new event",
            "acknowledgement": {
                "acknowledgerId": "ABC123",
                "acknowledger": "someone",
                "time": "2021-03-10T09:31:48Z"
            },
            "assignee": null,
            "assignment": {
                "assignee": "someone",
                "assigneeId": "ABC123",
                "time": "2021-03-10T09:31:48Z"
            },
            "created_at": "2021-03-10T09:31:48Z",
            "escalation_policy": "Default",
            "incident_key": "somekey",
            "last_status_change_at": "2021-03-10T10:00:50Z",
            "last_status_change_by": "API Service",
            "number_of_escalations": null,
            "resolve_reason": "",
            "resolved_by": null,
            "service_id": "someid",
            "service_name": "API Service",
            "teams": [],
            "urgency": "high"
        }
    }
}
```

#### Human Readable Output

>### PagerDuty Incident
>|ID|Title|Status|Created On|Urgency|Html Url|Incident key|Service ID|Service Name|Escalation Policy|Last Status Change On|Last Status Change By|Resolved By User|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| someid | [#281] my new event | acknowledged | 2021-03-10T09:31:48Z | high | https://demisto.pagerduty.com/incidents/someid | 8e42eeb6391a4a2abeda5d12e09bddec | someid | API Service | Default | 2021-03-10T10:00:50Z | API Service | - |


### PagerDuty-get-service-keys
***
Get Service keys for each of the services configured in the PagerDuty instance


#### Base Command

`PagerDuty-get-service-keys`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PagerDuty.Service.ID | string | The ID of the service connected to PagerDuty | 
| PagerDuty.Service.Name | string | The name of the service connected to PagerDuty | 
| PagerDuty.Service.Status | string | The status of the service connected to PagerDuty | 
| PagerDuty.Service.CreatedAt | date | The date in which the service connected to PagerDuty was created | 
| PagerDuty.Service.Integration.Name | string | The name of the integration used with the service | 
| PagerDuty.Service.Integration.Vendor | string | The name of the vendor for the integration used with the service.\(A value of 'Missing Vendor information' will appear once no information could be found\) | 
| PagerDuty.Service.Integration.Key | string | The key used to control events with the integration | 


#### Command Example
```!PagerDuty-get-service-keys```

#### Context Example
```json
{
    "PagerDuty": {
        "Service": [
            {
                "CreatedAt": "2016-03-20T14:00:55+02:00",
                "ID": "someid",
                "Integration": [
                    {
                        "Key": "somekey",
                        "Name": "API Service",
                        "Vendor": "Missing Vendor information"
                    }
                ],
                "Name": "API Service",
                "Status": "critical"
            }
        ]
    }
}
```

#### Human Readable Output

>### Service List
>|ID|Name|Status|Created At|Integration|
>|---|---|---|---|---|
>| someid | API Service | critical | 2016-03-20T14:00:55+02:00 | Name: API Service, Vendor: Missing Vendor information, Key: somekey<br/> |
