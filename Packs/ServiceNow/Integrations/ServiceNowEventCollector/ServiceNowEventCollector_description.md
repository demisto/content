Use this integration to collect audit logs automatically from ServiceNow.

To use ServiceNow on Cortex XSIAM, ensure your user account has the rest_api_explorer and web_service_admin roles.
These roles are required to make API calls.
However, they may not suffice for viewing records in some tables.
Please make sure you have the correct role so you have permissions to work with the relevant table.
  
### Instance Configuration
The integration supports two types of authorization:
1. Basic authorization using username and password.
2. OAuth 2.0 authorization.

#### OAuth 2.0 Authorization
To use OAuth 2.0 authorization follow the next steps:
1. Login to your ServiceNow instance and create an endpoint for XSIAM to access your instance (please see [Snow OAuth](https://docs.servicenow.com/bundle/orlando-platform-administration/page/administer/security/task/t_CreateEndpointforExternalClients.html) for more information). 
2. Copy the `Client Id` and `Client Secret` (press the lock next to the client secret to reveal it) that were automatically generated when creating the endpoint into the `ClientID` and `Client Secret` fields of the instance configuration.
3. Select the `Use OAuth Login` checkbox and click the `Done` button.
