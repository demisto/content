Celonis Event Collector is an integration that supports fetching audit log events.
This integration was integrated and tested with version 4.0 of Celonis.

## Configure Celonis in Cortex


| **Parameter** | **Description**                                                                                                                    | **Required** |
| --- |------------------------------------------------------------------------------------------------------------------------------------| --- |
| Server URL | The endpoint URL is constructed using the team name and realm in the format: https://&lt;teamname&gt;.&lt;realm&gt;.celonis.cloud. | True |
| Server URL | The endpoint URL is constructed using the team name and realm in the format: https://&lt;teamname&gt;.&lt;realm&gt;.celonis.cloud. | True |
| Client ID | The Client ID to use for connection.                                                                                               | True |
| Client Secret | The Client Secret to use for connection.                                                                                           | True |
| Trust any certificate (not secure) |                                                                                                                                    | False |
| Use system proxy settings |                                                                                                                                    | False |
| Maximum number of events per fetch | Defines the maximum number of audits events per fetch cycle. Default value: 600.                                                   | True |

API keys, passed in an HTTP header like this: Authorization: Bearer API_KEY.

#### How to create an OAuth client and generate client ID and Client Secret:
https://developer.celonis.com/celonis-apis/audit-log-api/#creating-an-application-and-granting-it-api-permissions
https://docs.celonis.com/en/using-oauth-2-0.html

1. To start, you need to create an OAuth client in your team and then grant this client API permissions.
2. Click **Admin & Settings** and select **Applications**.
3. Click **Add New Application - OAuth client** and create your OAuth client.
When creating your OAuth client, use the following configurations: **Authentication method: Client secret post**.
4. Select the following scopes:
   - **audit.log:read (For the Audit Log API)**.
   - **platform-adoption.tracking-events:read** (For the Studio Adoption API).
   - **team.login-history:read** (For the Login History API).
5. Click **Create** and then copy the client ID and client secret to your clipboard for later use.
6. Click **Permissions** and edit Team permissions.
7. Assign **Audit Log API**, ***Login History API**, and **Studio Adoption APIs** permissions to your newly created application as required.
8. Click **Save**.
The OAuth client now has the relevant API permissions. 

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### celonis-get-events

***
Retrieves a list of audit logs events from the Celonis instance.

#### Base Command

`celonis-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of events to return. | Required | 
| start_date | The starting date from which events should be fetched. The date should be in the format "YYYY-MM-DDTHH:MM:SS.sssZ". Example: 2025-02-04T10:33:24.647Z. | Required | 
| end_date | The date up to which events should be fetched. The date should be in the format "YYYY-MM-DDTHH:MM:SS.sssZ". Example: 2025-02-04T10:33:24.647Z. | Required | 

#### Context Output

| **Path**      | **Type** | **Description**                |
|---------------| --- |--------------------------------|
| Celonis.Audit | List | The list of audit logs events. | 

#### Command example
```!celonis-get-events should_push_events=false limit=10 end_date=2025-02-04T10:33:24.647Z start_date=2025-02-10T10:33:24.647Z```
