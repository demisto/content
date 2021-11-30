Integration with Atlassian OpsGenie
This integration was integrated and tested with OpsGenie

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-opsgenie-v3).

## Configure OpsGenie v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpsGenie v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://api.opsgenie.com) |  | True |
    | API Token | Must be created from the Teams API Integration section. | False |
    | Fetch incidents |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Max Fetch |  | False |
    | Event types | Fetch only events with selected event types | True |
    | Status | Fetch only events with selected status. If query is used, this paramter will be overrided. | False |
    | Priority | Fetch only events with selected priority. If query is used, this paramter will be overrided. | False |
    | Tags | Fetch only events with selected tags. If query is used, this paramter will be overrided. | False |
    | Query | Query parameters will be used as URL encoded values for “query” key. i.e. 'https://api.opsgenie.com/v2/alerts?query=status%3Aopenor%20acknowledged%3Atrue&amp;amp;limit=10&amp;amp;sort=createdAt' | False |
    | Incident type |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### opsgenie-create-alert
***
Create an Alert in opsgenie


#### Base Command

`opsgenie-create-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| max_results | The number of results to return. Default is 30. | Optional | 
| message | Alert message. | Required | 
| alias | Client-defined identifier of the alert. | Optional | 
| description | Description field of the alert that is generally used to provide a detailed information about the alert. | Optional | 
| responders | Teams/users that the alert is routed to via notifications.<br/> You need to insert it as List of triples - responder_type, value_type, value.<br/> The responder_type can be: team, user, escalation or schedule.<br/> The value_type can be: id or name.<br/> The value you can find from the output of the commands '!opsgenie-get-teams', '!opsgenie-get-schedules' or '!opsgenie-get-escalations'.<br/> For example: schedule,name,test_schedule,user,id,123,team,name,test_team. | Optional | 
| tags | Comma separated list of tags to add. | Optional | 
| priority | Incident Priority. Defaulted to P3 if not provided. Possible values are: P1, P2, P3, P4, P5. Default is P3. | Optional | 
| source | Display name of the request source. Defaulted to IP of the request sender. | Optional | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Alert.action | String | Action of this Request | 
| OpsGenie.Alert.alertId | String | Id of created Alert | 
| OpsGenie.Alert.alias | String | Alais of created Alert | 
| OpsGenie.Alert.integrationId | String | Integration of created Alert | 
| OpsGenie.Alert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Alert.processedAt | Date | When the request was processed | 
| OpsGenie.Alert.requestId | String | The ID of the request | 
| OpsGenie.Alert.status | String | The human readable result of the request | 
| OpsGenie.Alert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-create-alert message="Example Message"```

#### Context Example
```json
{
    "OpsGenie": {
        "Alert": {
            "requestId": "0dd92ee3-f6a1-4414-b4cf-098a644e2a1e"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=0dd92ee3-f6a1-4414-b4cf-098a644e2a1e

### opsgenie-get-alerts
***
List the current alerts from OpsGenie.


#### Base Command

`opsgenie-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Optional | 
| sort | Name of the field that result set will be sorted by.<br/> The options are: createdAt, updatedAt, tinyId, alias, message, status, acknowledged, isSeen snoozed, snoozedUntil, count, lastOccurredAt, source, owner, integration.name, integration.type, report.ackTime, report.closeTime, report.acknowledgedBy, report.closedBy. | Optional | 
| limit | Maximum results to return. Default is 20. | Optional | 
| offset | Start index of the result set (to apply pagination). Minimum value (and also default value) is 0. Default is 0. | Optional | 
| status | The status of the alert from opsgenie. Possible values are: Open, Closed. | Optional | 
| priority | The priority of the alert from opsgenie. Possible values are: P1, P2, P3, P4, P5. Default is P3. | Optional | 
| tags | Comma separated list of tags. | Optional | 
| query | URL Encoded query params. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Alert.acknowledged | Boolean | State of Acknoweledgement | 
| OpsGenie.Alert.alias | String | Alert Alias | 
| OpsGenie.Alert.count | Number | Count of Alert occurences | 
| OpsGenie.Alert.createdAt | Date | Time alert created | 
| OpsGenie.Alert.id | String | ID of alert | 
| OpsGenie.Alert.integration.id | String | ID of integration | 
| OpsGenie.Alert.integration.name | String | Integration name | 
| OpsGenie.Alert.integration.type | String | Type of integration | 
| OpsGenie.Alert.isSeen | Boolean | Whether alert has been seen | 
| OpsGenie.Alert.lastOccurredAt | Date | Time alert last occured | 
| OpsGenie.Alert.message | String | Alert Message | 
| OpsGenie.Alert.owner | String | Owner of Alert | 
| OpsGenie.Alert.ownerTeamId | String | Team ID of Owner | 
| OpsGenie.Alert.priority | String | Alert Priority | 
| OpsGenie.Alert.responders.id | String | ID of responders | 
| OpsGenie.Alert.responders.type | String | Type of Responders | 
| OpsGenie.Alert.seen | Boolean | Seen status of alert | 
| OpsGenie.Alert.snoozed | Boolean | Whether alert has been snoozed | 
| OpsGenie.Alert.source | String | Source of Alert | 
| OpsGenie.Alert.status | String | Status of Alert | 
| OpsGenie.Alert.teams.id | String | Id of teams associated with Alert | 
| OpsGenie.Alert.tinyId | String | Shorter ID for alert | 
| OpsGenie.Alert.updatedAt | Date | Last Updated time for Alert | 
| OpsGenie.Alert.report.ackTime | Number | Acknoweledgement Time of Alert | 
| OpsGenie.Alert.report.acknowledgedBy | String | User that Acknolwedged the alert | 
| OpsGenie.Alert.report.closeTime | Number | Time Alarm closed | 
| OpsGenie.Alert.report.closedBy | String | Who Closed the alarm | 


#### Command Example
```!opsgenie-get-alerts limit=1```

#### Context Example
```json
{
    "OpsGenie": {
        "Alert": [
            {
                "acknowledged": false,
                "alias": "f3dab429-9981-4d72-825a-5820e9973881-1637522513451",
                "count": 1,
                "createdAt": "2021-11-21T19:21:53.451Z",
                "event_type": "Alerts",
                "id": "f3dab429-9981-4d72-825a-5820e9973881-1637522513451",
                "integration": {
                    "id": "3cc69931-167f-411c-a331-768997c29d2e",
                    "name": "API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-11-21T19:21:53.451Z",
                "message": "123",
                "owner": "",
                "ownerTeamId": "",
                "priority": "P3",
                "responders": [
                    {
                        "id": "9a441a8d-2410-43f4-9ef2-f7a265e12b74",
                        "type": "escalation"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "92.168.x.x",
                "status": "open",
                "tags": [],
                "teams": [],
                "tinyId": "157",
                "updatedAt": "2021-11-21T19:26:53.705Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### OpsGenie Alert
>|acknowledged|alias|count|createdAt|event_type|id|integration|isSeen|lastOccurredAt|message|owner|ownerTeamId|priority|responders|seen|snoozed|source|status|tags|teams|tinyId|updatedAt|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | f3dab429-9981-4d72-825a-5820e9973881-1637522513451 | 1 | 2021-11-21T19:21:53.451Z | Alerts | f3dab429-9981-4d72-825a-5820e9973881-1637522513451 | id: 3cc69931-167f-411c-a331-768997c29d2e<br/>name: API<br/>type: API | false | 2021-11-21T19:21:53.451Z | 123 |  |  | P3 | {'type': 'escalation', 'id': '9a441a8d-2410-43f4-9ef2-f7a265e12b74'} | false | false | 92.168.x.x | open |  |  | 157 | 2021-11-21T19:26:53.705Z |


### opsgenie-delete-alert
***
Delete an Alert from OpsGenie


#### Base Command

`opsgenie-delete-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.DeletedAlert.action | String | Action of this Request | 
| OpsGenie.DeletedAlert.alertId | String | Id of deleted Alert | 
| OpsGenie.DeletedAlert.alias | String | Alais of deleted Alert | 
| OpsGenie.DeletedAlert.integrationId | String | Integration of deleted Alert | 
| OpsGenie.DeletedAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.DeletedAlert.processedAt | Date | When the request was processed | 
| OpsGenie.DeletedAlert.requestId | String | The ID of the request | 
| OpsGenie.DeletedAlert.status | String | The human readable result of the request | 
| OpsGenie.DeletedAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-delete-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286```

#### Context Example
```json
{
    "OpsGenie": {
        "DeletedAlert": {
            "requestId": "debec9e6-b5da-42f2-b83a-18a42486e3c3"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=debec9e6-b5da-42f2-b83a-18a42486e3c3

### opsgenie-ack-alert
***
Acknowledge an alert in OpsGenie


#### Base Command

`opsgenie-ack-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AckedAlert.action | String | Action of this Request | 
| OpsGenie.AckedAlert.alertId | String | Id of acked Alert | 
| OpsGenie.AckedAlert.alias | String | Alais of acked Alert | 
| OpsGenie.AckedAlert.integrationId | String | Integration of acked Alert | 
| OpsGenie.AckedAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AckedAlert.processedAt | Date | When the request was processed | 
| OpsGenie.AckedAlert.requestId | String | The ID of the request | 
| OpsGenie.AckedAlert.status | String | The human readable result of the request | 
| OpsGenie.AckedAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-ack-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286```

#### Context Example
```json
{
    "OpsGenie": {
        "AckedAlert": {
            "requestId": "58a5591c-94c2-45db-91db-674f434c3920"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=58a5591c-94c2-45db-91db-674f434c3920

### opsgenie-close-alert
***
Close an alert in OpsGenie


#### Base Command

`opsgenie-close-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.ClosedAlert.action | String | Action of this Request | 
| OpsGenie.ClosedAlert.alertId | String | Id of closed Alert | 
| OpsGenie.ClosedAlert.alias | String | Alais of closed Alert | 
| OpsGenie.ClosedAlert.integrationId | String | Integration of acked Alert | 
| OpsGenie.ClosedAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.ClosedAlert.processedAt | Date | When the request was processed | 
| OpsGenie.ClosedAlert.requestId | String | The ID of the request | 
| OpsGenie.ClosedAlert.status | String | The human readable result of the request | 
| OpsGenie.ClosedAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-close-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286```

#### Context Example
```json
{
    "OpsGenie": {
        "ClosedAlert": {
            "requestId": "f9b695e8-38f8-445a-a367-fe34ddc39642"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=f9b695e8-38f8-445a-a367-fe34ddc39642

### opsgenie-assign-alert
***
Assign an OpsGenie Alert


#### Base Command

`opsgenie-assign-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| owner_id | Id of User that the alert will be assigned to. Not required if owner_username is present. | Optional | 
| owner_username | Display name of the request owner. Not required if owner_id is present. | Optional | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AssignAlert.action | String | Action of this Request | 
| OpsGenie.AssignAlert.alertId | String | ID of assigned Alert | 
| OpsGenie.AssignAlert.alias | String | Alais of assigned Alert | 
| OpsGenie.AssignAlert.integrationId | String | Integration of assigned Alert | 
| OpsGenie.AssignAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AssignAlert.processedAt | Date | When the request was processed | 
| OpsGenie.AssignAlert.requestId | String | The ID of the request | 
| OpsGenie.AssignAlert.status | String | The human readable result of the request | 
| OpsGenie.AssignAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-assign-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 owner_username=b@g.com```

#### Context Example
```json
{
    "OpsGenie": {
        "AssignAlert": {
            "requestId": "8053a6a6-da2d-4488-b92c-eacd4640da15"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=8053a6a6-da2d-4488-b92c-eacd4640da15

### opsgenie-add-responder-alert
***
Add responder to an OpsGenie Alert


#### Base Command

`opsgenie-add-responder-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| identifierType | Type of the identifier. Possible values are: id, tiny, alias. | Optional | 
| responders | Team/user that the alert is routed to via notifications.<br/> For now, it can be inserted only one responder a time.<br/> You need to insert it as List of triple - responder_type, value_type, value.<br/> The responder_type can be: team or user.<br/> The value_type can be: id or name.<br/> The value you can find from the output of the command '!opsgenie-get-teams'.<br/> For example: user,id,123 Another example: team,name,test_team. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AddResponderAlert.action | String | Action of this Request | 
| OpsGenie.AddResponderAlert.alertId | String | ID of created Alert | 
| OpsGenie.AddResponderAlert.alias | String | Alais of created Alert | 
| OpsGenie.AddResponderAlert.integrationId | String | Integration of created Alert | 
| OpsGenie.AddResponderAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AddResponderAlert.processedAt | Date | When the request was processed | 
| OpsGenie.AddResponderAlert.requestId | String | The ID of the request | 
| OpsGenie.AddResponderAlert.status | String | The human readable result of the request | 
| OpsGenie.AddResponderAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-add-responder-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 responders=schedule,name,test_schedule```

#### Context Example
```json
{
    "OpsGenie": {
        "AddResponderAlert": {
            "requestId": "7fc0d0b5-532c-418d-b691-4bf9ca2d9411"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=7fc0d0b5-532c-418d-b691-4bf9ca2d9411

### opsgenie-get-escalations
***
Get escalations from OpsGenie


#### Base Command

`opsgenie-get-escalations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| escalation_id | Id of escalation. | Optional | 
| escalation_name | Name of escalation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Escalation.action | String | Action of this Request | 
| OpsGenie.Escalation.Id | String | ID of Escalation | 
| OpsGenie.Escalation.name | String | Name of Escalation | 
| OpsGenie.Escalation.description | String | Description of Escalation | 
| OpsGenie.Escalation.ownerTeam | String | OwnerTeam of Escalation | 
| OpsGenie.Escalation.rules | String | Rules of Escalation | 
| OpsGenie.Escalation.integrationId | String | Integration of escalated Alert | 
| OpsGenie.Escalation.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Escalation.processedAt | Date | When the request was processed | 
| OpsGenie.Escalation.requestId | String | The ID of the request | 
| OpsGenie.Escalation.status | String | The human readable result of the request | 
| OpsGenie.Escalation.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-get-escalations```

#### Context Example
```json
{
    "OpsGenie": {
        "Escalations": [
            {
                "description": "",
                "id": "9a441a8d-2410-43f4-9ef2-f7a265e12b74",
                "name": "Engineering_escalation",
                "ownerTeam": {
                    "id": "51d69df8-c40b-439e-9808-e1a78e54f91b",
                    "name": "Engineering"
                },
                "rules": [
                    {
                        "condition": "if-not-acked",
                        "delay": {
                            "timeAmount": 0,
                            "timeUnit": "minutes"
                        },
                        "notifyType": "default",
                        "recipient": {
                            "id": "7835aa84-7440-41d5-90bf-92e0045714d5",
                            "name": "Engineering_schedule",
                            "type": "schedule"
                        }
                    },
                    {
                        "condition": "if-not-acked",
                        "delay": {
                            "timeAmount": 5,
                            "timeUnit": "minutes"
                        },
                        "notifyType": "next",
                        "recipient": {
                            "id": "7835aa84-7440-41d5-90bf-92e0045714d5",
                            "name": "Engineering_schedule",
                            "type": "schedule"
                        }
                    },
                    {
                        "condition": "if-not-acked",
                        "delay": {
                            "timeAmount": 10,
                            "timeUnit": "minutes"
                        },
                        "notifyType": "all",
                        "recipient": {
                            "id": "51d69df8-c40b-439e-9808-e1a78e54f91b",
                            "name": "Engineering",
                            "type": "team"
                        }
                    }
                ]
            },
            {
                "description": "",
                "id": "c8a0f950-577c-4da5-894b-1fd463d9f51c",
                "name": "Integration Team_escalation",
                "ownerTeam": {
                    "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                    "name": "Integration Team"
                },
                "rules": [
                    {
                        "condition": "if-not-acked",
                        "delay": {
                            "timeAmount": 0,
                            "timeUnit": "minutes"
                        },
                        "notifyType": "default",
                        "recipient": {
                            "id": "df918339-b999-4878-b69b-3c2c0d508b01",
                            "name": "Integration Team_schedule",
                            "type": "schedule"
                        }
                    },
                    {
                        "condition": "if-not-acked",
                        "delay": {
                            "timeAmount": 1,
                            "timeUnit": "minutes"
                        },
                        "notifyType": "default",
                        "recipient": {
                            "id": "154d6425-c120-4beb-a3e6-a66c8c44f61d",
                            "type": "user",
                            "username": "dvilenchik@paloaltonetworks.com"
                        }
                    },
                    {
                        "condition": "if-not-acked",
                        "delay": {
                            "timeAmount": 5,
                            "timeUnit": "minutes"
                        },
                        "notifyType": "next",
                        "recipient": {
                            "id": "df918339-b999-4878-b69b-3c2c0d508b01",
                            "name": "Integration Team_schedule",
                            "type": "schedule"
                        }
                    },
                    {
                        "condition": "if-not-acked",
                        "delay": {
                            "timeAmount": 10,
                            "timeUnit": "minutes"
                        },
                        "notifyType": "all",
                        "recipient": {
                            "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                            "name": "Integration Team",
                            "type": "team"
                        }
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### OpsGenie Escalations
>|description|id|name|ownerTeam|rules|
>|---|---|---|---|---|
>|  | 9a441a8d-2410-43f4-9ef2-f7a265e12b74 | Engineering_escalation | id: 51d69df8-c40b-439e-9808-e1a78e54f91b<br/>name: Engineering | {'condition': 'if-not-acked', 'notifyType': 'default', 'delay': {'timeAmount': 0, 'timeUnit': 'minutes'}, 'recipient': {'type': 'schedule', 'id': '7835aa84-7440-41d5-90bf-92e0045714d5', 'name': 'Engineering_schedule'}},<br/>{'condition': 'if-not-acked', 'notifyType': 'next', 'delay': {'timeAmount': 5, 'timeUnit': 'minutes'}, 'recipient': {'type': 'schedule', 'id': '7835aa84-7440-41d5-90bf-92e0045714d5', 'name': 'Engineering_schedule'}},<br/>{'condition': 'if-not-acked', 'notifyType': 'all', 'delay': {'timeAmount': 10, 'timeUnit': 'minutes'}, 'recipient': {'type': 'team', 'id': '51d69df8-c40b-439e-9808-e1a78e54f91b', 'name': 'Engineering'}} |
>|  | c8a0f950-577c-4da5-894b-1fd463d9f51c | Integration Team_escalation | id: fbbc3f9a-12f4-4794-9938-7e0a85a06f8b<br/>name: Integration Team | {'condition': 'if-not-acked', 'notifyType': 'default', 'delay': {'timeAmount': 0, 'timeUnit': 'minutes'}, 'recipient': {'type': 'schedule', 'id': 'df918339-b999-4878-b69b-3c2c0d508b01', 'name': 'Integration Team_schedule'}},<br/>{'condition': 'if-not-acked', 'notifyType': 'default', 'delay': {'timeAmount': 1, 'timeUnit': 'minutes'}, 'recipient': {'type': 'user', 'id': '154d6425-c120-4beb-a3e6-a66c8c44f61d', 'username': 'dvilenchik@paloaltonetworks.com'}},<br/>{'condition': 'if-not-acked', 'notifyType': 'next', 'delay': {'timeAmount': 5, 'timeUnit': 'minutes'}, 'recipient': {'type': 'schedule', 'id': 'df918339-b999-4878-b69b-3c2c0d508b01', 'name': 'Integration Team_schedule'}},<br/>{'condition': 'if-not-acked', 'notifyType': 'all', 'delay': {'timeAmount': 10, 'timeUnit': 'minutes'}, 'recipient': {'type': 'team', 'id': 'fbbc3f9a-12f4-4794-9938-7e0a85a06f8b', 'name': 'Integration Team'}} |


### opsgenie-escalate-alert
***
Escalate an OpsGenie Alert


#### Base Command

`opsgenie-escalate-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| escalation_name | Escalation that the alert will be escalated. Either id or name of the escalation should be provided. | Optional | 
| escalation_id | Escalation that the alert will be escalated. Either id or name of the escalation should be provided. | Optional | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.EscalateAlert.action | String | Action of this Request | 
| OpsGenie.EscalateAlert.id | String | ID of escalation | 
| OpsGenie.EscalateAlert.name | String | Name of Escalation | 
| OpsGenie.EscalateAlert.description | String | Description of Escalation | 
| OpsGenie.EscalateAlert.integrationId | String | Integration of escalated Alert | 
| OpsGenie.EscalateAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.EscalateAlert.processedAt | Date | When the request was processed | 
| OpsGenie.EscalateAlert.requestId | String | The ID of the request | 
| OpsGenie.EscalateAlert.status | String | The human readable result of the request | 
| OpsGenie.EscalateAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-escalate-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 escalation_id=9a441a8d-2410-43f4-9ef2-f7a265e12b74```

#### Context Example
```json
{
    "OpsGenie": {
        "EscalateAlert": {
            "requestId": "fc77c05d-8616-48f6-a0ac-ac91bfe12e14"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=fc77c05d-8616-48f6-a0ac-ac91bfe12e14

### opsgenie-add-alert-tag
***
Add tag into OpsGenie Alert


#### Base Command

`opsgenie-add-alert-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| tags | Comma separated list of tags to add into alert. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AddTagAlert.action | String | Action of this Request | 
| OpsGenie.AddTagAlert.alertId | String | ID of added Alert | 
| OpsGenie.AddTagAlert.alias | String | Alais of added Alert | 
| OpsGenie.AddTagAlert.integrationId | String | Integration of added Alert | 
| OpsGenie.AddTagAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AddTagAlert.processedAt | Date | When the request was processed | 
| OpsGenie.AddTagAlert.requestId | String | The ID of the request | 
| OpsGenie.AddTagAlert.status | String | The human readable result of the request | 
| OpsGenie.AddTagAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-add-alert-tag alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 tags=1,2,3```

#### Context Example
```json
{
    "OpsGenie": {
        "AddTagAlert": {
            "requestId": "0a96f900-578d-4ae1-b73a-979838622ae4"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=0a96f900-578d-4ae1-b73a-979838622ae4

### opsgenie-remove-alert-tag
***
Remove tag from OpsGenie Alert


#### Base Command

`opsgenie-remove-alert-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| tags | Comma separated list of tags to remove from alert. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.RemoveTagAlert.action | String | Action of this Request | 
| OpsGenie.RemoveTagAlert.alertId | String | ID of removed tag Alert | 
| OpsGenie.RemoveTagAlert.alias | String | Alais of removed tag Alert | 
| OpsGenie.RemoveTagAlert.integrationId | String | Integration of removed tag Alert | 
| OpsGenie.RemoveTagAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.RemoveTagAlert.processedAt | Date | When the request was processed | 
| OpsGenie.RemoveTagAlert.requestId | String | The ID of the request | 
| OpsGenie.RemoveTagAlert.status | String | The human readable result of the request | 
| OpsGenie.RemoveTagAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-remove-alert-tag alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 tags=1,2,3```

#### Context Example
```json
{
    "OpsGenie": {
        "AckedAlert": {
            "action": "Acknowledge",
            "alertId": "",
            "alias": "",
            "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
            "isSuccess": false,
            "processedAt": "2021-11-21T19:31:37.653Z",
            "status": "Alert does not exist",
            "success": false
        },
        "RemoveTagAlert": {
            "requestId": "38b09db6-cfab-486d-83ad-4da8e8182d81"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=38b09db6-cfab-486d-83ad-4da8e8182d81

### opsgenie-get-alert-attachments
***
Get allert attachments


#### Base Command

`opsgenie-get-alert-attachments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| attachment_id | Identifier of the attachment. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Alert.Attachment.action | String | Action of this Request | 
| OpsGenie.Alert.Attachment.alertId | String | ID of Alert | 
| OpsGenie.Alert.Attachment.alias | String | Alais of Alert | 
| OpsGenie.Alert.Attachment.integrationId | String | Integration of Alert | 
| OpsGenie.Alert.Attachment.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Alert.Attachment.processedAt | Date | When the request was processed | 
| OpsGenie.Alert.Attachment.requestId | String | The ID of the request | 
| OpsGenie.Alert.Attachment.status | String | The human readable result of the request | 
| OpsGenie.Alert.Attachment.success | Boolean | Bool, whether the request was a success | 


#### Command Example
``` ```

#### Human Readable Output



### opsgenie-get-schedules
***
Get dchedules from OpsGenie


#### Base Command

`opsgenie-get-schedules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | Id of schedule. | Optional | 
| schedule_name | Name of schedule. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Schedule.description | String | Schedule description | 
| OpsGenie.Schedule.enabled | Boolean | If schedule enabled | 
| OpsGenie.Schedule.id | String | Id of schedule | 
| OpsGenie.Schedule.name | String | Name of schedule | 
| OpsGenie.Schedule.ownerTeam.id | String | Id of schedule owner | 
| OpsGenie.Schedule.ownerTeam.name | String | Name of schedule owner | 
| OpsGenie.Schedule.timezone | String | Schedule timezone | 


#### Command Example
```!opsgenie-get-schedules```

#### Context Example
```json
{
    "OpsGenie": {
        "Schedule": [
            {
                "description": "Schedule when escalation was activated",
                "enabled": true,
                "id": "5892636c-6183-4788-99d6-6d93b9095194",
                "name": "Escalation Schedule",
                "ownerTeam": {
                    "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                    "name": "Integration Team"
                },
                "rotations": [],
                "timezone": "Asia/Jerusalem"
            },
            {
                "description": "",
                "enabled": true,
                "id": "7835aa84-7440-41d5-90bf-92e0045714d5",
                "name": "Engineering_schedule",
                "ownerTeam": {
                    "id": "51d69df8-c40b-439e-9808-e1a78e54f91b",
                    "name": "Engineering"
                },
                "rotations": [],
                "timezone": "Asia/Jerusalem"
            },
            {
                "description": "24/7 Shift",
                "enabled": true,
                "id": "df918339-b999-4878-b69b-3c2c0d508b01",
                "name": "Integration Team_schedule",
                "ownerTeam": {
                    "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                    "name": "Integration Team"
                },
                "rotations": [],
                "timezone": "Asia/Jerusalem"
            }
        ]
    }
}
```

#### Human Readable Output

>### OpsGenie Schedule
>|description|enabled|id|name|ownerTeam|rotations|timezone|
>|---|---|---|---|---|---|---|
>| Schedule when escalation was activated | true | 5892636c-6183-4788-99d6-6d93b9095194 | Escalation Schedule | id: fbbc3f9a-12f4-4794-9938-7e0a85a06f8b<br/>name: Integration Team |  | Asia/Jerusalem |
>|  | true | 7835aa84-7440-41d5-90bf-92e0045714d5 | Engineering_schedule | id: 51d69df8-c40b-439e-9808-e1a78e54f91b<br/>name: Engineering |  | Asia/Jerusalem |
>| 24/7 Shift | true | df918339-b999-4878-b69b-3c2c0d508b01 | Integration Team_schedule | id: fbbc3f9a-12f4-4794-9938-7e0a85a06f8b<br/>name: Integration Team |  | Asia/Jerusalem |


### opsgenie-get-schedule-overrides
***
Get schedule overrides


#### Base Command

`opsgenie-get-schedule-overrides`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | Id of schedule. | Optional | 
| schedule_name | Name of schedule. | Optional | 
| override_alias | Alias of the schedule override. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Schedule.Override.action | String | Action of this Request | 
| OpsGenie.Schedule.Override.alertId | String | ID of Schedule | 
| OpsGenie.Schedule.Override.alias | String | Alais of Schedule | 
| OpsGenie.Schedule.Override.integrationId | String | Integration of Alert | 
| OpsGenie.Schedule.Override.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Schedule.Override.processedAt | Date | When the request was processed | 
| OpsGenie.Schedule.Override.requestId | String | The ID of the request | 
| OpsGenie.Schedule.Override.status | String | The human readable result of the request | 
| OpsGenie.Schedule.Override.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-get-schedule-overrides schedule_id=5892636c-6183-4788-99d6-6d93b9095194```

#### Context Example
```json
{
    "OpsGenie": {
        "AddTagAlert": {
            "action": "Add Tags",
            "alertId": "",
            "alias": "",
            "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
            "isSuccess": false,
            "processedAt": "2021-11-21T19:31:46.991Z",
            "status": "Alert does not exist",
            "success": false
        }
    }
}
```

#### Human Readable Output

>### OpsGenie Schedule
>**No entries.**


### opsgenie-get-on-call
***
Get the on-call users for the provided schedule


#### Base Command

`opsgenie-get-on-call`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | Schedule id from which to return on-call users. | Optional | 
| schedule_name | Schedule name from which to return on-call users. | Optional | 
| starting_date | Starting date of the timeline that will be provided in format as (yyyy-MM-dd'T'HH:mm:ssZ). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Schedule.OnCall._parent.enabled | Boolean | If this OnCall is Enabled | 
| OpsGenie.Schedule.OnCall._parent.id | String | ID Of parent schedule | 
| OpsGenie.Schedule.OnCall._parent.name | String | Name of parent Schedule | 
| OpsGenie.Schedule.OnCall.onCallParticipants.id | String | ID Of oncall participant | 
| OpsGenie.Schedule.OnCall.onCallParticipants.name | String | Name of oncall participant | 
| OpsGenie.Schedule.OnCall.onCallParticipants.type | String | Type of OnCall participant | 


#### Command Example
```!opsgenie-get-on-call schedule_id=5892636c-6183-4788-99d6-6d93b9095194```

#### Context Example
```json
{
    "OpsGenie": {
        "Schedule": {
            "OnCall": {
                "data": {
                    "_parent": {
                        "enabled": true,
                        "id": "5892636c-6183-4788-99d6-6d93b9095194",
                        "name": "Escalation Schedule"
                    },
                    "onCallParticipants": [
                        {
                            "id": "154d6425-c120-4beb-a3e6-a66c8c44f61d",
                            "name": "dvilenchik@paloaltonetworks.com",
                            "type": "user"
                        }
                    ]
                },
                "requestId": "e04f123b-f9cd-4d29-951e-ca6943987e67",
                "took": 0.016
            }
        }
    }
}
```

#### Human Readable Output

>### OpsGenie Schedule OnCall
>|_parent|onCallParticipants|
>|---|---|
>| id: 5892636c-6183-4788-99d6-6d93b9095194<br/>name: Escalation Schedule<br/>enabled: true | {'id': '154d6425-c120-4beb-a3e6-a66c8c44f61d', 'name': 'dvilenchik@paloaltonetworks.com', 'type': 'user'} |


### opsgenie-create-incident
***
Create an Incident in opsgenie


#### Base Command

`opsgenie-create-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| message | Incident message. | Required | 
| description | Description field of the incident that is generally used to provide a detailed information about it. | Optional | 
| responders | Teams/users that the incident is routed to via notifications.<br/> You need to insert it as List of triples - responder_type, value_type, value.<br/> The responder_type can be: team or user.<br/> The value_type can be: id or name.<br/> The value you can find from the output of the command '!opsgenie-get-teams'.<br/> For example: user,id,123,team,name,test_team. | Optional | 
| tags | Comma separated list of tags to add. | Optional | 
| priority | Incident Priority. Defaulted to P3 if not provided. Possible values are: P1, P2, P3, P4, P5. Default is P3. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Incident.action | String | Action of this Request | 
| OpsGenie.Incident.incidentId | String | Id of created incident | 
| OpsGenie.Incident.integrationId | String | Integration of created Alert | 
| OpsGenie.Incident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Incident.processedAt | Date | When the request was processed | 
| OpsGenie.Incident.requestId | String | The ID of the request | 
| OpsGenie.Incident.status | String | The human readable result of the request | 
| OpsGenie.Incident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-create-incident message="test" responders=team,name,test_team,team,name,test_team_1```

#### Context Example
```json
{
    "OpsGenie": {
        "Incident": {
            "requestId": "66340811-6de2-4594-8532-74b3fe7d89d4"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=66340811-6de2-4594-8532-74b3fe7d89d4

### opsgenie-delete-incident
***
Delete an incident from OpsGenie


#### Base Command

`opsgenie-delete-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.DeletedIncident.action | String | Action of this Request | 
| OpsGenie.DeletedIncident.incidnetId | String | Id of deleted incident | 
| OpsGenie.DeletedIncident.integrationId | String | Integration of deleted incident | 
| OpsGenie.DeletedIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.DeletedIncident.processedAt | Date | When the request was processed | 
| OpsGenie.DeletedIncident.requestId | String | The ID of the request | 
| OpsGenie.DeletedIncident.status | String | The human readable result of the request | 
| OpsGenie.DeletedIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-delete-incident incident_id=c59086e0-bf2c-44e2-bdfb-ed7747cc126b```

#### Context Example
```json
{
    "OpsGenie": {
        "DeletedIncident": {
            "requestId": "a01676ee-93e1-4615-b986-b0091b70cdc2"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=a01676ee-93e1-4615-b986-b0091b70cdc2

### opsgenie-get-incidents
***
List the current incidents from OpsGenie.


#### Base Command

`opsgenie-get-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Optional | 
| limit | Maximum results to return. Default is 20. | Optional | 
| offset | Start index of the result set (to apply pagination). Minimum value (and also default value) is 0. Default is 0. | Optional | 
| status | The ID of the alert from opsgenie. Possible values are: Open, Closed. | Optional | 
| priority | Incident Priority. Defaulted to P3 if not provided. Possible values are: P1, P2, P3, P4, P5. Default is P3. | Optional | 
| tags | Comma separated list of tags to add. | Optional | 
| query | URL Encoded query params. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Incident.count | Number | Count of Alert occurences | 
| OpsGenie.Incident.createdAt | Date | Time alert created | 
| OpsGenie.Incident.incidentId | String | ID of alert | 
| OpsGenie.Incident.integration.id | String | ID of integration | 
| OpsGenie.Incident.integration.name | String | Integration name | 
| OpsGenie.Incident.integration.type | String | Type of integration | 
| OpsGenie.Incident.message | String | Alert Message | 
| OpsGenie.Incident.ownerTeam | String | Team ID of Owner | 
| OpsGenie.Incident.priority | String | Alert Priority | 
| OpsGenie.Incident.responders.id | String | ID of responders | 
| OpsGenie.Incident.responders.type | String | Type of Responders | 
| OpsGenie.Incident.status | String | Status of Alert | 
| OpsGenie.Incident.tinyId | String | Shorter ID for alert | 
| OpsGenie.Incident.updatedAt | Date | Last Updated time for Alert | 


#### Command Example
```!opsgenie-get-incidents limit=1```

#### Context Example
```json
{
    "OpsGenie": {
        "Incident": [
            {
                "actions": [],
                "createdAt": "2021-11-21T19:32:02.148Z",
                "description": "",
                "event_type": "Incidents",
                "extraProperties": {},
                "id": "2a1c07ea-b9bd-4922-afcc-edf406b46904",
                "impactStartDate": "2021-11-21T19:32:02.148Z",
                "impactedServices": [],
                "links": {
                    "api": "https://api.opsgenie.com/v1/incidents/2a1c07ea-b9bd-4922-afcc-edf406b46904",
                    "web": "https://demisto1.app.opsgenie.com/incident/detail/2a1c07ea-b9bd-4922-afcc-edf406b46904"
                },
                "message": "test",
                "ownerTeam": "",
                "priority": "P3",
                "responders": [],
                "status": "open",
                "tags": [],
                "tinyId": "86",
                "updatedAt": "2021-11-21T19:32:02.148Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### OpsGenie Incident
>|actions|createdAt|description|event_type|extraProperties|id|impactStartDate|impactedServices|links|message|ownerTeam|priority|responders|status|tags|tinyId|updatedAt|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 2021-11-21T19:32:02.148Z |  | Incidents |  | 2a1c07ea-b9bd-4922-afcc-edf406b46904 | 2021-11-21T19:32:02.148Z |  | web: https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/2a1c07ea-b9bd-4922-afcc-edf406b46904<br/>api: https:<span>//</span>api.opsgenie.com/v1/incidents/2a1c07ea-b9bd-4922-afcc-edf406b46904 | test |  | P3 |  | open |  | 86 | 2021-11-21T19:32:02.148Z |


### opsgenie-close-incident
***
Close an incident from OpsGenie


#### Base Command

`opsgenie-close-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| note | Additional incident note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.ClosedIncident.action | String | Action of this Request | 
| OpsGenie.ClosedIncident.incidentId | String | Id of closed incident | 
| OpsGenie.ClosedIncident.integrationId | String | Integration of closed incident | 
| OpsGenie.ClosedIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.ClosedIncident.processedAt | Date | When the request was processed | 
| OpsGenie.ClosedIncident.requestId | String | The ID of the request | 
| OpsGenie.ClosedIncident.status | String | The human readable result of the request | 
| OpsGenie.ClosedIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-close-incident incident_id=c59086e0-bf2c-44e2-bdfb-ed7747cc126b```

#### Context Example
```json
{
    "OpsGenie": {
        "ClosedIncident": {
            "requestId": "81abe974-7265-4a46-90cd-ebf560b4fa63"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=81abe974-7265-4a46-90cd-ebf560b4fa63

### opsgenie-resolve-incident
***
Resolve an incident from OpsGenie


#### Base Command

`opsgenie-resolve-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| note | Additional incident note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.ResolvedIncident.action | String | Action of this Request | 
| OpsGenie.ResolvedIncident.incidentId | String | Id of closed incident | 
| OpsGenie.ResolvedIncident.integrationId | String | Integration of closed incident | 
| OpsGenie.ResolvedIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.ResolvedIncident.processedAt | Date | When the request was processed | 
| OpsGenie.ResolvedIncident.requestId | String | The ID of the request | 
| OpsGenie.ResolvedIncident.status | String | The human readable result of the request | 
| OpsGenie.ResolvedIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-resolve-incident incident_id=b15c7555-d685-4a96-8798-46320618004e```

#### Context Example
```json
{
    "OpsGenie": {
        "ResolvedIncident": {
            "requestId": "3c4da8b6-79f4-42ab-b478-24f9fc9febd7"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=3c4da8b6-79f4-42ab-b478-24f9fc9febd7

### opsgenie-add-responder-incident
***
Add responder to an OpsGenie Incident


#### Base Command

`opsgenie-add-responder-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| responders | Teams/users that the incident is routed to via notifications.<br/> You need to insert it as List of triples - responder_type, value_type, value.<br/> The responder_type can be: team or user.<br/> The value_type can be: id or name.<br/> The value you can find from the output of the command '!opsgenie-get-teams'.<br/> For example: user,id,123,team,name,test_team. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AddResponderIncident.action | String | Action of this Request | 
| OpsGenie.AddResponderIncident.incidentId | String | ID of created Incident | 
| OpsGenie.AddResponderIncident.integrationId | String | Integration of created Incident | 
| OpsGenie.AddResponderIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AddResponderIncident.processedAt | Date | When the request was processed | 
| OpsGenie.AddResponderIncident.requestId | String | The ID of the request | 
| OpsGenie.AddResponderIncident.status | String | The human readable result of the request | 
| OpsGenie.AddResponderIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-add-responder-incident incident_id=577424c1-b03c-4d23-9871-da0d395fea17 responders="team,name,Integration Team"```

#### Context Example
```json
{
    "OpsGenie": {
        "AddResponderIncident": {
            "requestId": "71020660-17b3-4ce0-9cf2-825496a3141c"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=71020660-17b3-4ce0-9cf2-825496a3141c

### opsgenie-add-tag-incident
***
Add tag into OpsGenie Incident


#### Base Command

`opsgenie-add-tag-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| tags | Comma separated list of tags to add into incident. | Required | 
| note | Additional incident note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AddTagIncident.action | String | Action of this Request | 
| OpsGenie.AddTagIncident.incidentId | String | ID of added Incident | 
| OpsGenie.AddTagIncident.integrationId | String | Integration of added Incident | 
| OpsGenie.AddTagIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AddTagIncident.processedAt | Date | When the request was processed | 
| OpsGenie.AddTagIncident.requestId | String | The ID of the request | 
| OpsGenie.AddTagIncident.status | String | The human readable result of the request | 
| OpsGenie.AddTagIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-add-tag-incident incident_id=b15c7555-d685-4a96-8798-46320618004e tags=1,2,3```

#### Context Example
```json
{
    "OpsGenie": {
        "AddTagIncident": {
            "requestId": "f19257ff-2156-4649-b074-ca44dfa7cc31"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=f19257ff-2156-4649-b074-ca44dfa7cc31

### opsgenie-remove-tag-incident
***
Remove tag from OpsGenie Alert


#### Base Command

`opsgenie-remove-tag-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| tags | Comma separated list of tags to add into incident. | Required | 
| note | Additional incident note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.RemoveTagIncident.action | String | Action of this Request | 
| OpsGenie.RemoveTagIncident.incidentId | Stringx | ID of removed tag Incident | 
| OpsGenie.RemoveTagIncident.integrationId | String | Integration of removed tag Incident | 
| OpsGenie.RemoveTagIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.RemoveTagIncident.processedAt | Date | When the request was processed | 
| OpsGenie.RemoveTagIncident.requestId | String | The ID of the request | 
| OpsGenie.RemoveTagIncident.status | String | The human readable result of the request | 
| OpsGenie.RemoveTagIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-remove-tag-incident incident_id=b15c7555-d685-4a96-8798-46320618004e tags=1,2```

#### Context Example
```json
{
    "OpsGenie": {
        "DeletedIncident": {
            "action": "Delete",
            "incidentId": "",
            "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
            "isSuccess": false,
            "processedAt": "2021-11-21T19:32:05.17Z",
            "status": "",
            "success": false
        },
        "RemoveTagIncident": {
            "requestId": "691aa626-c2e2-4404-ba88-b9e888861c5e"
        }
    }
}
```

#### Human Readable Output

>Waiting for request_id=691aa626-c2e2-4404-ba88-b9e888861c5e

### opsgenie-get-teams
***
Get teams


#### Base Command

`opsgenie-get-teams`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | The ID of the team from opsgenie. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Team.description | String | Team description | 
| OpsGenie.Team.id | String | Team id | 
| OpsGenie.Team.links.api | String | Team api links | 
| OpsGenie.Team.links.web | String | Team web links | 
| OpsGenie.Team.name | String | Team name | 


#### Command Example
```!opsgenie-get-teams```

#### Context Example
```json
{
    "OpsGenie": {
        "Team": [
            {
                "description": "Engineering",
                "id": "51d69df8-c40b-439e-9808-e1a78e54f91b",
                "links": {
                    "api": "https://api.opsgenie.com/v2/teams/51d69df8-c40b-439e-9808-e1a78e54f91b",
                    "web": "https://demisto1.app.opsgenie.com/teams/dashboard/51d69df8-c40b-439e-9808-e1a78e54f91b/main"
                },
                "name": "Engineering"
            },
            {
                "description": "Integration Team",
                "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                "links": {
                    "api": "https://api.opsgenie.com/v2/teams/fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                    "web": "https://demisto1.app.opsgenie.com/teams/dashboard/fbbc3f9a-12f4-4794-9938-7e0a85a06f8b/main"
                },
                "name": "Integration Team"
            }
        ]
    }
}
```

#### Human Readable Output

>### OpsGenie Team
>|description|id|links|name|
>|---|---|---|---|
>| Engineering | 51d69df8-c40b-439e-9808-e1a78e54f91b | web: https:<span>//</span>demisto1.app.opsgenie.com/teams/dashboard/51d69df8-c40b-439e-9808-e1a78e54f91b/main<br/>api: https:<span>//</span>api.opsgenie.com/v2/teams/51d69df8-c40b-439e-9808-e1a78e54f91b | Engineering |
>| Integration Team | fbbc3f9a-12f4-4794-9938-7e0a85a06f8b | web: https:<span>//</span>demisto1.app.opsgenie.com/teams/dashboard/fbbc3f9a-12f4-4794-9938-7e0a85a06f8b/main<br/>api: https:<span>//</span>api.opsgenie.com/v2/teams/fbbc3f9a-12f4-4794-9938-7e0a85a06f8b | Integration Team |


## Breaking changes from the previous version of this integration - OpsGenie v3
There were added new commands and fetch-commands.

### Commands
#### The following commands were removed in this version:
* *opsgenie-list-alerts* - this command was replaced by *opsgenie-get-alerts*.
* *opsgenie-get-alert* - this command was replaced by *opsgenie-get-alerts*.
* *opsgenie-get-schedule* - this command was replaced by *opsgenie-get-schedules*.
* *opsgenie-list-schedules* - this command was replaced by *opsgenie-get-schedules*.

### Arguments
#### The following arguments were removed in this version:

In the *opsgenie-get-on-call* command:
* *schedule-id* - this argument was replaced by *schedule_id* and *schedule_name*.

#### The behavior of the following arguments was changed:

In the *opsgenie-create-alert* command:
* *priority* - The default value changed to 'P3'.

### Outputs
#### The following outputs were removed in this version:

In the *opsgenie-create-alert* command:
* *OpsGenieV2.CreatedAlert.action* - this output was replaced by *OpsGenie.Alert.action*.
* *OpsGenieV2.CreatedAlert.alertId* - this output was replaced by *OpsGenie.Alert.alertId*.
* *OpsGenieV2.CreatedAlert.alias* - this output was replaced by *OpsGenie.Alert.alias*.
* *OpsGenieV2.CreatedAlert.integrationId* - this output was replaced by *OpsGenie.Alert.integrationId*.
* *OpsGenieV2.CreatedAlert.isSuccess* - this output was replaced by *OpsGenie.Alert.isSuccess*.
* *OpsGenieV2.CreatedAlert.processedAt* - this output was replaced by *OpsGenie.Alert.processedAt*.
* *OpsGenieV2.CreatedAlert.requestId* - this output was replaced by *OpsGenie.Alert.requestId*.
* *OpsGenieV2.CreatedAlert.status* - this output was replaced by *OpsGenie.Alert.status*.
* *OpsGenieV2.CreatedAlert.success* - this output was replaced by *OpsGenie.Alert.success*.

In the *opsgenie-delete-alert* command:
* *OpsGenieV2.DeletedAlert.action* - this output was replaced by *OpsGenie.DeletedAlert.action*.
* *OpsGenieV2.DeletedAlert.alertId* - this output was replaced by *OpsGenie.DeletedAlert.alertId*.
* *OpsGenieV2.DeletedAlert.alias* - this output was replaced by *OpsGenie.DeletedAlert.alias*.
* *OpsGenieV2.DeletedAlert.integrationId* - this output was replaced by *OpsGenie.DeletedAlert.integrationId*.
* *OpsGenieV2.DeletedAlert.isSuccess* - this output was replaced by *OpsGenie.DeletedAlert.isSuccess*.
* *OpsGenieV2.DeletedAlert.processedAt* - this output was replaced by *OpsGenie.DeletedAlert.processedAt*.
* *OpsGenieV2.DeletedAlert.requestId* - this output was replaced by *OpsGenie.DeletedAlert.requestId*.
* *OpsGenieV2.DeletedAlert.status* - this output was replaced by *OpsGenie.DeletedAlert.status*.
* *OpsGenieV2.DeletedAlert.success* - this output was replaced by *OpsGenie.DeletedAlert.success*.

In the *opsgenie-ack-alert* command:
* *OpsGenieV2.AckedAlert.action* - this output was replaced by *OpsGenie.AckedAlert.action*.
* *OpsGenieV2.AckedAlert.alertId* - this output was replaced by *OpsGenie.AckedAlert.alertId*.
* *OpsGenieV2.AckedAlert.alias* - this output was replaced by *OpsGenie.AckedAlert.alias*.
* *OpsGenieV2.AckedAlert.integrationId* - this output was replaced by *OpsGenie.AckedAlert.integrationId*.
* *OpsGenieV2.AckedAlert.isSuccess* - this output was replaced by *OpsGenie.AckedAlert.isSuccess*.
* *OpsGenieV2.AckedAlert.processedAt* - this output was replaced by *OpsGenie.AckedAlert.processedAt*.
* *OpsGenieV2.AckedAlert.requestId* - this output was replaced by *OpsGenie.AckedAlert.requestId*.
* *OpsGenieV2.AckedAlert.status* - this output was replaced by *OpsGenie.AckedAlert.status*.
* *OpsGenieV2.AckedAlert.success* - this output was replaced by *OpsGenie.AckedAlert.success*.

In the *opsgenie-get-on-call* command:
* *OpsGenieV2.OnCall._parent.enabled* - this output was replaced by *OpsGenie.Schedule.OnCall._parent.enabled*.
* *OpsGenieV2.OnCall._parent.id* - this output was replaced by *OpsGenie.Schedule.OnCall._parent.id*.
* *OpsGenieV2.OnCall._parent.name* - this output was replaced by *OpsGenie.Schedule.OnCall._parent.name*.
* *OpsGenieV2.OnCall.onCallParticipants.id* - this output was replaced by *OpsGenie.Schedule.OnCall.onCallParticipants.id*.
* *OpsGenieV2.OnCall.onCallParticipants.name* - this output was replaced by *OpsGenie.Schedule.OnCall.onCallParticipants.name*.
* *OpsGenieV2.OnCall.onCallParticipants.type* - this output was replaced by *OpsGenie.Schedule.OnCall.onCallParticipants.type*.

In the *opsgenie-close-alert* command:
* *OpsGenieV2.CloseAlert.action* - this output was replaced by *OpsGenie.ClosedAlert.action*.
* *OpsGenieV2.CloseAlert.alertId* - this output was replaced by *OpsGenie.ClosedAlert.alertId*.
* *OpsGenieV2.CloseAlert.alias* - this output was replaced by *OpsGenie.ClosedAlert.alias*.
* *OpsGenieV2.CloseAlert.integrationId* - this output was replaced by *OpsGenie.ClosedAlert.integrationId*.
* *OpsGenieV2.CloseAlert.isSuccess* - this output was replaced by *OpsGenie.ClosedAlert.isSuccess*.
* *OpsGenieV2.CloseAlert.processedAt* - this output was replaced by *OpsGenie.ClosedAlert.processedAt*.
* *OpsGenieV2.CloseAlert.requestId* - this output was replaced by *OpsGenie.ClosedAlert.requestId*.
* *OpsGenieV2.CloseAlert.status* - this output was replaced by *OpsGenie.ClosedAlert.status*.
* *OpsGenieV2.CloseAlert.success* - this output was replaced by *OpsGenie.ClosedAlert.success*.
