This integration supports three authentication methods:

1. **Basic Authentication:** Deprecated starting from version 10.35.0 of Jamf. 
Use `username and password` - the credentials of a user with relevant permissions in your Jamf Pro admin console. 
Basic Authentication needs to be enabled by the user in the Jamf Pro admin console (not recommended). For more information, click [here](https://developer.jamf.com/jamf-pro/docs/classic-api-authentication-changes).

2. **Bearer Token based on Basic Authentication:** This method applies to Jamf versions 10.35.0 and above. 
Use `username and password` - the credentials of a user with relevant permissions in your Jamf Pro admin console.

3. **Bearer Token based on Client Credentials:** This method applies to Jamf versions 10.49.0 and above. 
Use `client ID` and `client secret`. Refer to this [link](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) for instructions on retrieving a client ID and client secret.

*Important Note:* Before creating an API client, ensure that you create an API role with all the required privileges as mentioned in the integration documentation. Then, associate the API client with that role.

*Note:* If the second method is used, the system will automatically attempt to generate a token. If this attempt fails, it will then revert to using the first method.