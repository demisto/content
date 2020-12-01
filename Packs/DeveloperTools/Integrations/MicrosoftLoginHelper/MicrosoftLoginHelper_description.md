## Microsoft Initialize Instance Helper Integration
- This integration is used in order to test Microsoft Azure and Microsoft Graph integrations 
that are using the `device token` flow. This integration gets a user, password and tenant as parameters
and client_id (or app_id) as a command argument and returns the refresh token for that user.
Using this token the integration can initialize for tests. 

For referance look at `Azure Network Security Groups` integration 
