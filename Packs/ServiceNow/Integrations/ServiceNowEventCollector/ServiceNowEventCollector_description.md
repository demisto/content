Use this integration to collect audit and syslog transactions logs automatically from ServiceNow.

To use ServiceNow on Cortex XSIAM, ensure your user account has the rest_api_explorer and web_service_admin roles.
These roles are required to make API calls.
However, they may not suffice for viewing records in some tables.
Please make sure you have the correct role so you have permissions to work with the relevant table.
  
### Instance Configuration
The integration supports two types of authorization:
1. Basic authorization using username and password.
2. OAuth 2.0 authorization.

#### OAuth 2.0 Authorization
To use OAuth 2.0 authorization:
1. Log in to your ServiceNow instance and create an endpoint for Cortex XSIAM to access your instance. For more information, see [Snow OAuth](https://docs.servicenow.com/bundle/orlando-platform-administration/page/administer/security/task/t_CreateEndpointforExternalClients.html) . 
2. Click the lock next to the Client Secret to reveal it.
3. Copy the `Client Id` and `Client Secret` into the `ClientID` and `Client Secret` fields of the instance configuration. The `Client Id` and `Client Secret` were automatically generated when you created the endpoint.
4. Select the `Use OAuth Login` checkbox and click `Done`.
