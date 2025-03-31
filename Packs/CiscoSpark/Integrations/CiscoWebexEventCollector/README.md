Cisco Webex Event Collector fetches Events and Admin Audit Events and Security Audit Events.
This integration was integrated and tested with version 1 of CiscoWebex API.

## Configure Cisco Webex Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Automation & Feed Integrations**.
2. Search for Cisco Webex Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | URL |  | True |
    | Admin APP Client ID | Admin APP Client ID and Secret. | True |
    | Admin APP Client Secret |  | True |
    | Admin APP Redirect URI |  | True |
    | Admin Org Id |  | True |
    | Compliance Officer Client ID | Compliance Officer Client ID and Secret. | True |
    | Compliance Officer Client Secret |  | True |
    | Compliance Officer Redirect URI |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch security audit events | To fetch security audit events, the Pro Pack must be installed on the Webex instance, and *Allow user authentication data* must be enabled. See the note below. | False |
    | Maximum number of events per fetch |  | False |

4. 
    1. Run the ***cisco-webex-oauth-start*** command with the **user** argument - you will be prompted to sign in to Cisco Webex with your username and password. (make sure you sign in with the same user as you defined in the user argument `admin` or `compliance officer`). You will then be redirected to the `redirect URI` you defined in the application. The URL will contain a query parameter called `code`. The value of this query parameter will be used in the next command. 
    2. Run the ***cisco-webex-oauth-complete*** command with the **user** and **code** arguments The **user** argument should be set to the same value as in the previous command (`admin` or `compliance officer`). The **code** argument should be set to the value returned in the code query parameter from the previous command.
    3. Run the ***cisco-webex-oauth-test*** command with the **user** argument. The **user** argument should be set to the same value as in the previous command (`admin` or `compliance officer`) to ensure connectivity to Cisco Webex.

   **Note:** To fetch *security audit events*, the Pro Pack must be installed on the Webex instance. Additionally, the *Allow user authentication data* setting must be enabled:

     Go to Management > Organization Settings.
        In the User authentication data section, toggle Allow user authentication data ON.
        For more details, refer to the [official documentation.](https://help.webex.com/en-us/article/pf66vg/Log-and-analyze-user-sign-ins-and-sign-outs)

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
| user | The user to start authorization. Possible values are: admin, compliance_officer. | Required | 

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
| user | The user to complete authorization. Possible values are: admin, compliance_officer. | Required | 
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
| user | The user to complete authorization. Possible values are: admin, compliance_officer. | Required | 

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
| since_datetime | Date in ISO format (2023-10-01T20:33:22.123Z) to return events from. | Optional | 

#### Human Readable Output

### Admin Audit Events

|_time|actorId|actorOrgId|created|data|id|source_log_type|
|---|---|---|---|---|---|---|
| 2023-11-02T09:33:26.408Z | 444444 | 222222 | 2023-11-02T09:33:26.408Z | actorOrgName: panw<br>targetName: panw<br>operationType: CREATE<br>eventDescription: An org setting was created or updated.<br>actorName: admin@example.com<br>actorEmail: admin@example.com<br>settingKey: release_migration<br>settingName: release_migration<br>settingValue: "MIGRATED"<br>trackingId: 111111<br>previousValue: Null<br>targetType: ORG<br>targetId: 222222<br>actorUserAgent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/2.2.2.2 Safari/537.36<br>eventCategory: ORG_SETTINGS<br>actorIp: 1.1.1.1<br>targetOrgId: 222222<br>actionText: admin@example.com has modified the value of setting release_migration for ORG "panw". New value = "MIGRATED", Previous value = Null.<br>entityType: ORG<br>targetOrgName: panw | 333333 | Admin Audit Events |

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
| since_datetime | Date in ISO format (2023-10-01T20:33:22.123Z) to return events from. | Optional | 

#### Human Readable Output

### Security Audit Events

|_time|actorId|actorOrgId|created|data|id|source_log_type|
|---|---|---|---|---|---|---|
| 2023-12-19T07:01:26.486Z | 444444 | 222222 | 2023-12-19T07:01:26.486Z | actorOrgName: panw<br>eventDescription: A user attempted logging in<br>actorName: admin@example.com<br>actorEmail: admin@example.com<br>authenticationMethod: Non-Interactive<br>trackingId: 123456<br>eventStatus: SUCCESS<br>actorOauthClient: 111111<br>actorUserAgent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36<br>eventCategory: LOGINS<br>actorIp: 1.1.1.1<br>actorClientName: Developer Portal<br>actionText: admin@example.com attempted logging into panw using client (Developer Portal) and Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36. Login status: SUCCESS.  <br>failedReason:   | 333333 | Security Audit Events |

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
| since_datetime | Date in ISO format (2023-10-01T20:33:22.123Z) to return events from. | Optional | 

#### Human Readable Output

### Events

|_time|actorId|created|data|id|resource|source_log_type|type|
|---|---|---|---|---|---|---|---|
| 2023-11-05T13:33:46.417Z | 222222 | 2023-11-05T13:33:46.417Z | id: 333333<br>roomId: 444444<br>roomType: group<br>personId: 222222<br>personEmail: ksolberg@paloaltonetworks.com<br>personDisplayName: Kfir Solberg<br>personOrgId: 555555<br>isModerator: false<br>isMonitor: false<br>isRoomHidden: false<br>created: 2023-11-05T13:33:46.417Z | 111111 | memberships | Events | created |

#### Context Output

There is no context output for this command.
