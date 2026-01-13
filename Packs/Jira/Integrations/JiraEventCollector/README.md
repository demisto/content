This integration was integrated and tested with version 3 of Jira Event Collector rest API.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Jira Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | For Jira Cloud with OAuth 2.0, use `https://api.atlassian.com/ex/jira`. For on-prem instances, use your Jira server URL. | True |
| Authentication Method | Select the authentication method: Basic or OAuth 2.0. Default is Basic. | False |
| User name | The user name for Basic Authentication (e.g., `admin@example.com`) | False |
| API token | The API token for Basic Authentication | False |
| Cloud ID | Required for Jira Cloud instances using OAuth 2.0. Find your Cloud ID at https://admin.atlassian.com. Leave empty for On-Prem instances. | False |
| Callback URL | The redirect URL for OAuth 2.0 (e.g., `https://localhost/myapp`) | False |
| Client ID | OAuth 2.0 Client ID | False |
| Client Secret | OAuth 2.0 Client Secret | False |
| First fetch time | (&lt;number&gt; &lt;time unit&gt;. For example, 12 hours, 1 day, 3 months). Default is 3 days. | True |
| The maximum number of events per fetch | Default is 1000. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Authentication Methods

### Basic Authentication
1. Set **Authentication Method** to `Basic`
2. Provide your **User name** (email address)
3. Provide your **API token** (generate from Jira account settings)
4. Set the **Server URL** to your Jira instance URL

### OAuth 2.0 Authentication (Recommended)
OAuth 2.0 provides more secure authentication with limited scopes, avoiding the need for global administrator permissions.

#### For Jira Cloud

**Required OAuth Scopes**:
- **Classic (Recommended)**: `manage:jira-configuration`
- **Granular**: `read:audit-log:jira`, `read:user:jira`

**Setup Steps**:
1. **Create OAuth 2.0 App in Jira Cloud**:
   - Go to https://developer.atlassian.com/console/myapps/
   - Create a new OAuth 2.0 integration app
   - Configure the callback URL (e.g., `https://localhost/myapp`)
   - Add the required scopes
   - Note your Client ID and Client Secret

2. **Configure Integration**:
   - Set **Authentication Method** to `OAuth 2.0`
   - Set **Server URL** to `https://api.atlassian.com/ex/jira`
   - Enter your **Cloud ID** (find at https://admin.atlassian.com)
   - Enter the **Callback URL** (same as configured in OAuth app)
   - Enter **Client ID** and **Client Secret**

3. **Complete Authorization**:
   - Run the command: `!jira-oauth-start`
   - Click the authorization URL in the response
   - Authorize the application
   - Copy the authorization code from the callback URL
   - Run: `!jira-oauth-complete code=<your_code>`

4. **Test Connection**:
   - Run: `!jira-oauth-test`
   - Or use the Test button in the integration configuration

#### For Jira On-Prem/Data Center

**Required OAuth Scopes**:
- `WRITE` (provides read and write access)

**Setup Steps**:
1. **Create OAuth 2.0 App in Jira On-Prem**:
   - Go to Jira Administration → Applications → Application Links
   - Create an incoming application link
   - Configure OAuth 2.0 settings
   - Set the callback URL (e.g., `https://localhost/myapp`)
   - Note your Client ID and Client Secret

2. **Configure Integration**:
   - Set **Authentication Method** to `OAuth 2.0`
   - Set **Server URL** to your Jira server URL (e.g., `https://jira.company.com`)
   - Leave **Cloud ID** empty (not used for on-prem)
   - Enter the **Callback URL** (same as configured in OAuth app)
   - Enter **Client ID** and **Client Secret**

3. **Complete Authorization**:
   - Run the command: `!jira-oauth-start`
   - Click the authorization URL in the response
   - Authorize the application
   - Copy the authorization code from the callback URL
   - Run: `!jira-oauth-complete code=<your_code>`

4. **Test Connection**:
   - Run: `!jira-oauth-test`
   - Or use the Test button in the integration configuration

**Note**: On-Prem OAuth uses PKCE (Proof Key for Code Exchange) for enhanced security.

## Commands

You can execute these commands from the War Room, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### jira-oauth-start

***
Start the OAuth 2.0 authorization process. Returns an authorization URL.

#### Base Command

`jira-oauth-start`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example

```!jira-oauth-start```

#### Human Readable Output

>### Authorization Instructions
>1. Click on the following link to authorize:
>https://auth.atlassian.com/authorize?...
>
>2. After authorizing, you will be redirected to the callback URL
>3. Copy the authorization code from the 'code' parameter in the URL
>4. Run the command: `!jira-oauth-complete code=<your_code>`

---

### jira-oauth-complete

***
Complete the OAuth 2.0 authorization process using the authorization code.

#### Base Command

`jira-oauth-complete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | The authorization code received from the OAuth callback | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!jira-oauth-complete code=abc123xyz```

#### Human Readable Output

>### Successfully authenticated!
>The access token and refresh token have been saved.
>You can now use the integration to fetch events.

---

### jira-oauth-test

***
Test the OAuth 2.0 authentication.

#### Base Command

`jira-oauth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example

```!jira-oauth-test```

#### Human Readable Output

>✓ Authentication successful

---

### jira-get-events

***

#### Base Command

`jira-get-events`

#### Input

| **Argument Name** | **Description**                                                                                          | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------|--------------|
| max_fetch         | The maximum number of events per fetch. Default is 1000.                                 | Optional     |
| first_fetch       | First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 1 day, 3 months). default is 3 days. | Optional     |

#### Command example

```!jira-get-events max_fetch=2```

#### Context Example

```json
{
    "Jira": {
        "Records": [
            {
                "associatedItems": [
                    {
                        "id": "ug:123456-123456-123456",
                        "name": "ug:123456-123456-123456",
                        "parentId": "111",
                        "parentName": "com.atlassian.crowd.directory.example",
                        "typeName": "USER"
                    }
                ],
                "category": "group management",
                "created": "2022-04-24T16:28:53.146+0000",
                "eventSource": "",
                "id": 1111,
                "objectItem": {
                    "name": "jira-servicemanagement-users",
                    "parentId": "111",
                    "parentName": "com.atlassian.crowd.directory.example",
                    "typeName": "GROUP"
                },
                "summary": "User added to group"
            },
            {
                "associatedItems": [
                    {
                        "id": "ug:123456-123456-123457",
                        "name": "ug:123456-123456-123457",
                        "parentId": "111",
                        "parentName": "com.atlassian.crowd.directory.example",
                        "typeName": "USER"
                    }
                ],
                "category": "group management",
                "created": "2022-04-24T16:28:53.098+0000",
                "eventSource": "",
                "id": 1110,
                "objectItem": {
                    "name": "jira-software-users",
                    "parentId": "111",
                    "parentName": "com.atlassian.crowd.directory.example",
                    "typeName": "GROUP"
                },
                "summary": "User added to group"
            }
        ]
    }
}
```

#### Human Readable Output

>### Jira records
>
>|Associated Items|Category|Created| Id   | Object Item                                                                                                                    |Summary|
>|---|---|------|--------------------------------------------------------------------------------------------------------------------------------|---|---|
>| {'id': 'ug:123456-123456-123456', 'name': 'ug:123456-123456-123456', 'typeName': 'USER', 'parentId': '111', 'parentName': 'com.atlassian.crowd.directory.example'} | group management | 2022-04-24T16:28:53.146+0000 | 1111 | name: jira-servicemanagement-users<br/>typeName: GROUP<br/>parentId: 111<br/>parentName: com.atlassian.crowd.directory.example | User added to group |
>| {'id': 'ug:123456-123456-123457', 'name': 'ug:123456-123456-123457', 'typeName': 'USER', 'parentId': '111', 'parentName': 'com.atlassian.crowd.directory.example'} | group management | 2022-04-24T16:28:53.098+0000 | 1110 | name: jira-software-users<br/>typeName: GROUP<br/>parentId: 111<br/>parentName: com.atlassian.crowd.directory.example          | User added to group |
