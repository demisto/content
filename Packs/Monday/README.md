# Monday

Monday.com is a work operating system that powers teams to run projects and workflows with confidence. Use this pack to fetch activity and audit logs from Monday.com for threat detection and compliance monitoring in Cortex XSIAM.

## What does this pack do?

- **Activity Logs Collection**: Monitor user activities, board interactions, and workspace changes using OAuth 2.0 authentication.
- **Audit Logs Collection**: Track administrative actions, security events, and compliance-related activities using API token authentication.

- **Audit and Activity Logs** modeling rules.

## How to collect Monday.com audit logs and activity events

## Required Permissions

To use this integration, the following permissions are required on the Monday.com app.  

- `boards:read`

### Activity log

[Activity log API docs](https://developer.monday.com/api-reference/reference/activity-logs)

Can be accessed using the OAuth [method](https://developer.monday.com/apps/docs/choosing-auth#method-2-using-oauth-to-issue-access-tokens).

Create your Monday app [guidelines](https://developer.monday.com/apps/docs/create-an-app#creating-an-app-in-the-developer-center) and make sure the needed permissions are granted for the app registration:
Required scope - boards:read
The Redirect URI - https://localhost

Enter your Client ID and Client Secret in the instance parameter fields.

Run the ***!monday-generate-login-url*** command in the War Room and follow the instructions:

To sign in, click the login URL and grant Cortex XSIAM permissions. You will be automatically redirected to a link with the following structure:
REDIRECT_URI?code=AUTH_CODE&region=REGION&scope=boards%3Aread&state=

Copy the AUTH_CODE (without the code= prefix) and paste it in your instance configuration under the Authorization code parameter.

Save the instance.
In the Playground, run the ***!monday-auth-test*** command. A 'Success' message is generated.

### Audit log

[Audit log API docs](https://support.monday.com/hc/en-us/articles/4406042650002-Audit-Log-API)

Generating the API token

1. Access the Admin section of your account.
2. Click Security, and then select the Audit tab.
3. Select Monitor by API.
4. Copy the generated API token.

Audit log is an advanced security feature and available on the Enterprise plan and can only be accessed by the account admin.

## Configure MondayEventCollector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Activity logs Server URL |  | False |
| Client ID |  | False |
| Client secret |  | False |
| Authorization code | The code received from the redirect URL after running monday-generate-login-url command. \(needed for Activity Logs only\) | False |
| Board IDs | Comma separated list of board IDs. \(needed for Activity Logs only\) | False |
| Events Fetch Interval |  | False |
| Maximum number of Activity Logs per board per fetch |  | False |
| Audit Server URL |  | False |
| Audit API token | In the Admin section of your account, click the 'Security' section and then the 'Audit' tab. Select the 'Monitor by API' button. | False |
| Maximum number of Audit Logs per fetch |  | False |
| Fetch events |  | False |
| Event types |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### monday-generate-login-url

***
Generate the login url used for Authorization code flow.

#### Base Command

`monday-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!monday-generate-login-url```

#### Human Readable Output

>### Authorization instructions
>
>1. To sign in, click the login URL and grant Cortex XSIAM permissions.
You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&region=REGION&scope=boards%3Aread&state=```
>2. Copy the `AUTH_CODE` (without the `code=` prefix) and paste it in your instance configuration under the **Authorization code** parameter.

### monday-auth-test

***
Run this command to test the connectivity to Monday.

#### Base Command

`monday-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!monday-auth-test```

#### Human Readable Output

>✅ Success!

## Pack Contents

- `MondayEventCollector` integration - integrates with Monday.com API to fetch logs.

## Supported Event Types

### Activity Logs

Activity logs capture user interactions and operational activities within Monday.com workspaces:

- Board creation, updates, and deletions
- Item and column modifications
- User login and authentication events
- Workspace and team changes
- File uploads and sharing activities

### Audit Logs

Audit logs provide detailed security and administrative event tracking:

- Administrative actions and configuration changes
- User permission modifications
- Security policy updates
- Account management activities
- Compliance and governance events

## Additional Resources

- [Monday.com API Documentation](https://developer.monday.com/api-reference/docs)
- [OAuth 2.0 Authentication Guide](https://developer.monday.com/apps/docs/choosing-auth#method-2-using-oauth-to-issue-access-tokens)
- [Audit Log API Documentation](https://support.monday.com/hc/en-us/articles/4406042650002-Audit-Log-API)
- [Activity Log API Documentation](https://developer.monday.com/api-reference/reference/activity-logs)
- [Monday.com App Creation Guide](https://developer.monday.com/apps/docs/create-an-app#creating-an-app-in-the-developer-center)
