Cisco Webex Event Collector fetches Events and Admin Audit Events and Security Audit Events.
This integration was integrated and tested with version xx of CiscoWebexEventCollector.

## Configure Cisco Webex Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Automation & Feed Integrations**.
2. Search for Cisco Webex Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Admin APP Client ID | Admin APP Client ID and Secret. | True |
    | Admin APP Client Secret |  | True |
    | Admin APP Redirect URI |  | True |
    | Admin Org Id |  | True |
    | Compliance Officer Client ID | Compliance Officer Client ID and Secret. | True |
    | Compliance Officer Client Secret |  | True |
    | Compliance Officer Redirect URI |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Maximum number of events per fetch |  | False |

4. Run the **!cisco-webex-oauth-start** (and follow the instructions) to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-webex-oauth-start

***
Use this command to start the authorization process. In order to authorize the instance, first run the command, and complete the process in the URL that is returned. You will then be redirected to the callback URL where you will copy the authorization code found in the query parameter `code`, and paste that value in the command `!cisco-webex-oauth-complete` as an argument to finish the process.

#### Base Command

`cisco-webex-oauth-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | The user to start authenticate. Possible values are: admin, compliance_officer. | Required | 

#### Context Output

There is no context output for this command.
### cisco-webex-oauth-complete

***
Use this command to complete the authorization process. After copying the authorization code found in the query parameter `code` of the callback URL, paste the value in the command as an argument to finish the process.

#### Base Command

`cisco-webex-oauth-complete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | The user to complete authenticate. Possible values are: admin, compliance_officer. | Required | 
| code | The authorization code retrieved from the callback URL according to the documentation. | Required | 

#### Context Output

There is no context output for this command.
### cisco-webex-oauth-test

***
Use this command to complete the authorization process. After copying the authorization code found in the query parameter `code` of the callback URL, paste the value in the command as an argument to finish the process.

#### Base Command

`cisco-webex-oauth-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | The user to complete authenticate. Possible values are: admin, compliance_officer. | Required | 

#### Context Output

There is no context output for this command.
### cisco-webex-get-admin-audit-events

***
Gets admin audit events from Cisco Webex.

#### Base Command

`cisco-webex-get-admin-audit-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of events to return. | Optional | 
| since_datetime | Date to return events from. | Optional | 

#### Human Readable Output

### Admin Audit Events

|Administrator|Description|EventTime|Feature|InternalSessionId|LoggedAt|LoggedFrom|PermissionDescription|Role|SetName|_time|eventTypeXsiam|
|---|---|---|---|---|---|---|---|---|---|---|---|
| admin@paloaltonetworks.com | API Get Admin audit data /API/Sets/47f5830e-383a-4db1-9e5f-b38ed0448a92/AdminAudit?dateFrom=2023-12-17T12:17:35.384Z&limit=250 GET DateFrom: 2023-12-17T12:17:35.384Z, DateTo: , offset: 0, limit: 250 | 2023-12-17T12:38:26.53Z | Public API | 239076 | 2023-12-14T13:09:49.81Z | 1.1.1.1 | None | SetUser | PANW Production(palo alto networks inc.) | 2023-12-17T12:38:26.53Z | set admin audit data |
| admin@paloaltonetworks.com | API Get Admin audit data /API/Sets/47f5830e-383a-4db1-9e5f-b38ed0448a92/AdminAudit?dateFrom=2023-12-17T12:38:01.454Z&limit=250 GET DateFrom: 2023-12-17T12:38:01.454Z, DateTo: , offset: 0, limit: 250 | 2023-12-17T12:39:26.703Z | Public API | 239076 | 2023-12-14T13:09:49.81Z | 1.1.1.1 | None | SetUser | PANW Production(palo alto networks inc.) | 2023-12-17T12:39:26.703Z | set admin audit data |

#### Context Output

There is no context output for this command.
### cisco-webex-get-security-audit-events

***
Gets security audit events from Cisco Webex.

#### Base Command

`cisco-webex-get-security-audit-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of events to return. | Optional | 
| since_datetime | Date to return events from. | Optional | 

#### Human Readable Output

### Security Audit Events

|Administrator|Description|EventTime|Feature|InternalSessionId|LoggedAt|LoggedFrom|PermissionDescription|Role|SetName|_time|eventTypeXsiam|
|---|---|---|---|---|---|---|---|---|---|---|---|
| admin@paloaltonetworks.com | API Get Admin audit data /API/Sets/47f5830e-383a-4db1-9e5f-b38ed0448a92/AdminAudit?dateFrom=2023-12-17T12:17:35.384Z&limit=250 GET DateFrom: 2023-12-17T12:17:35.384Z, DateTo: , offset: 0, limit: 250 | 2023-12-17T12:38:26.53Z | Public API | 239076 | 2023-12-14T13:09:49.81Z | 1.1.1.1 | None | SetUser | PANW Production(palo alto networks inc.) | 2023-12-17T12:38:26.53Z | set admin audit data |
| admin@paloaltonetworks.com | API Get Admin audit data /API/Sets/47f5830e-383a-4db1-9e5f-b38ed0448a92/AdminAudit?dateFrom=2023-12-17T12:38:01.454Z&limit=250 GET DateFrom: 2023-12-17T12:38:01.454Z, DateTo: , offset: 0, limit: 250 | 2023-12-17T12:39:26.703Z | Public API | 239076 | 2023-12-14T13:09:49.81Z | 1.1.1.1 | None | SetUser | PANW Production(palo alto networks inc.) | 2023-12-17T12:39:26.703Z | set admin audit data |

#### Context Output

There is no context output for this command.
### cisco-webex-get-compliance-officer-events

***
Gets events from Cisco Webex.

#### Base Command

`cisco-webex-get-compliance-officer-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of events to return. | Optional | 
| since_datetime | Date to return events from. | Optional | 

#### Human Readable Output

### Events

|Administrator|Description|EventTime|Feature|InternalSessionId|LoggedAt|LoggedFrom|PermissionDescription|Role|SetName|_time|eventTypeXsiam|
|---|---|---|---|---|---|---|---|---|---|---|---|
| admin@paloaltonetworks.com | API Get Admin audit data /API/Sets/47f5830e-383a-4db1-9e5f-b38ed0448a92/AdminAudit?dateFrom=2023-12-17T12:17:35.384Z&limit=250 GET DateFrom: 2023-12-17T12:17:35.384Z, DateTo: , offset: 0, limit: 250 | 2023-12-17T12:38:26.53Z | Public API | 239076 | 2023-12-14T13:09:49.81Z | 1.1.1.1 | None | SetUser | PANW Production(palo alto networks inc.) | 2023-12-17T12:38:26.53Z | set admin audit data |
| admin@paloaltonetworks.com | API Get Admin audit data /API/Sets/47f5830e-383a-4db1-9e5f-b38ed0448a92/AdminAudit?dateFrom=2023-12-17T12:38:01.454Z&limit=250 GET DateFrom: 2023-12-17T12:38:01.454Z, DateTo: , offset: 0, limit: 250 | 2023-12-17T12:39:26.703Z | Public API | 239076 | 2023-12-14T13:09:49.81Z | 1.1.1.1 | None | SetUser | PANW Production(palo alto networks inc.) | 2023-12-17T12:39:26.703Z | set admin audit data |

#### Context Output

There is no context output for this command.
