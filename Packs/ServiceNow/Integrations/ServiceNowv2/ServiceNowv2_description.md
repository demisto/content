 To use ServiceNow on Demisto, ensure your user account has the rest_api_explorer and web_service_admin roles.
 These roles are required to make API calls.
 However, they may not suffice for viewing records in some tables.
 Please make sure you have the correct role so you have permissions to work with the relevant table.
  
### Instance Configuration
The integration supports two types of authorization:
1. Basic authorization using username and password.
2. OAuth 2.0 authorization.

#### OAuth 2.0 Authorization
To use OAuth 2.0 authorization follow the next steps:
1. Login to your service-now instance and create an endpoint for XSOAR to access your instance (please see [Snow OAuth](https://docs.servicenow.com/bundle/orlando-platform-administration/page/administer/security/task/t_CreateEndpointforExternalClients.html) for more information). 
2. Copy the client id and client secret that were automatically generated when creating the endpoint into the `Username` and `Password` fields respectively.
3. Check the `Use OAuth` checkbox.
4. Run the command `!servicenow-login` from the XSOAR CLI and fill in the username and password.
5. (Optional) Test the created instance by running the `!servicenow-oauth-test` command.

