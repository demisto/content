### Instance Configuration
The integration supports two types of authorization:
1. Basic authorization using username and password.
2. OAuth 2.0 authorization.

#### OAuth 2.0 Authorization
To use OAuth 2.0 authorization perform the following steps:
1. Login to your ServiceNow instance and create an endpoint for XSOAR to access your instance. (See [Snow OAuth](https://docs.servicenow.com/bundle/orlando-platform-administration/page/administer/security/task/t_CreateEndpointforExternalClients.html) for more information). 
2. Copy the **Client Id** and **Client Secret** (press the lock next to the client secret to reveal it) that were automatically generated when creating the endpoint into the **Username** and **Password** fields of the instance configuration.
3. Select the **Use OAuth Login** checkbox and click **Done**.
4. Run the command ***!servicenow-cmdb-oauth-login*** from the XSOAR CLI and fill in the username and password of the ServiceNow instance. This step generates and saves in the integration context a refresh token to the ServiceNow instance and is required only the first time you configure a new instance in the XSOAR platform.
5. (Optional) Test the created instance by running the ***!servicenow-cmdb-oauth-test*** command.

**Notes:**
1. When running the ***!servicenow-cmdb-oauth-login*** command, a refresh token is generated and will be used to produce new access tokens after the current access token has expired.
2. Every time the refresh token expires you will have to run the ***servicenow-cmdb-oauth-login*** command again. Therefore, we recommend to set the **Refresh Token Lifespan** field in the endpoint created in step 1 to a long period (can be set to several years). 


### Using Multi Factor Authentication (MFA)
MFA can be used both when using basic authorization and when using OAuth 2.0 authorization, however we strongly recommend using OAuth 2.0 when using MFA.
If MFA is enabled for your user, perform the following steps:
1. Open the Google Authenticator application on your mobile device and make note of the number. The number refreshes every 30 seconds.
2. Enter your username and password, and append the One Time Password (OTP) that you currently see on your mobile device to your password without any extra spaces. For example, if your password is **12345** and the current OTP code is **424 058**, enter `12345424058`.

**Notes:**
1. When using basic authorization, you will have to update your password with the current OTP every time the current code expires (30 seconds), therefore we recommend using OAuth 2.0 authorization.
2. For using OAuth 2.0 see the instructions above. The OTP code should be appended to the password parameter in the ***!servicenow-cmdb-oauth-login*** command.
