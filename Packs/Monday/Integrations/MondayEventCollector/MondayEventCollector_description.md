### Activity log

[Activity log API docs](https://developer.monday.com/api-reference/reference/activity-logs)

can be accessed using the OAuth [method](https://developer.monday.com/apps/docs/choosing-auth#method-2-using-oauth-to-issue-access-tokens).

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
