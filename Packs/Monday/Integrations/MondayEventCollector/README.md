Collects Monday.com audit logs and activity events for Cortex XSIAM.

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
To generate the audit log API token, access the admin section of your account, click the "Security" section, and then the "Audit" tab. From there, select the "Monitor by API" button and copy it.

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
