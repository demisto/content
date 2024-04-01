This integration supports three authentication methods:

1. **Basic authentication:** Deprecated starting from version *10.35.0* of Jamf. For more information, click [here](https://developer.jamf.com/jamf-pro/docs/classic-api-authentication-changes).


2. **Bearer token based on basic authentication:** This method is applicable for Jamf versions 10.35.0 and above.
Use `username and password`.
The username and password of a user with relevant permissions to your Jamf Pro admin console.
3. **Bearer token based on client credentials:** This method is applicable for Jamf versions 10.49.0 and above.
Use `client ID and client secret`.
See this [link](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) for how to retrieve a client ID and client secret.

*Important*: Before creating an API client, ensure that you create an API role with all the privileges as mentioned in the integration documentation. Then, associate the API client with that role.

When using the first two methods, provide a username and password. The system will automatically attempt to generate a token (second method), and if unsuccessful, it will fallback to using the first method, but only if basic authentication is permitted by the user.