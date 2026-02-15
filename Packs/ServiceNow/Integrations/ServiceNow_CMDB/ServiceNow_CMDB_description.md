### Instance Configuration
The integration supports two types of authorization:
1. Basic authorization using username and password.
2. OAuth 2.0 authorization.
3. JWT Authentication.

#### OAuth 2.0 Authorization
To use OAuth 2.0 authorization perform the following steps:
1. Login to your ServiceNow instance and create an endpoint for XSOAR to access your instance. (See [Snow OAuth](https://docs.servicenow.com/bundle/xanadu-platform-security/page/administer/security/concept/c_OAuthApplications.html) for more information).
2. Copy the **Client Id** and **Client Secret** (press the lock next to the client secret to reveal it) that were automatically generated when creating the endpoint into the **Client ID** and **Client Secret** fields of the instance configuration.
3. (Recommended) Enter the ServiceNow account's **Username** and **Password** in the instance configuration. When provided, the integration will automatically perform the initial OAuth login on first use — no manual ***!servicenow-cmdb-oauth-login*** command is needed. It will also automatically renew the refresh token when it expires.
4. Select the **Use OAuth Login** checkbox and click **Done**.
5. If you did **not** provide **Username** and **Password** in step 3, run the command ***!servicenow-cmdb-oauth-login*** from the XSOAR CLI and fill in the username and password of the ServiceNow instance. This step generates and saves in the integration context a refresh token to the ServiceNow instance and is required only the first time you configure a new instance in the XSOAR platform. If you provided **Username** and **Password**, this step is handled automatically.
6. (Optional) Test the created instance by running the ***!servicenow-cmdb-oauth-test*** command.

**Notes:**
1. When running the ***!servicenow-cmdb-oauth-login*** command, a refresh token is generated and will be used to produce new access tokens after the current access token has expired.
2. If the **Username** and **Password** fields are configured, the integration will automatically perform the initial login and renew the refresh token when it expires — no manual commands are needed. Otherwise, you will have to run the ***servicenow-cmdb-oauth-login*** command for the initial login and again each time the refresh token expires. We recommend setting the **Refresh Token Lifespan** field in the endpoint created in step 1 to a long period (can be set to several years).
3. The grant type used to get an access token is `Client credentials`. See the [Snow documentation](https://docs.servicenow.com/bundle/xanadu-platform-security/page/administer/security/concept/c_OAuthApplications.html#d25788e201) for more information.

#### JWT Authentication
##### Prerequisites in order to support JWT

1. Create a Java Key Store and upload it to the instance by accessing from the upper menu: **All** > **System Definition** > **Certificates**. The private key will be used as an integration parameter. 
2. Configure a JWT signing key by accessing: All→System OAuth→JWT Keys using the keystore from above and keep the Key ID as it will be used as kid integration parameter. 
3. Create a JWT provider with a JWT signing key by accessing: All→System OAuth→JWT providers. Claim Name sub in Standard Claims has to be existing non-admin servicenow user with all necessary roles.
4. Connect to an OAuth provider and create an OAuth application registry by accessing All→System OAuth→Application Registry: 
   1. aud in JWT provider has to be equal to Client ID from OAuth JWT application - update JWT provider If necessary. 
   2. The value of kid in JWT Verifier Maps has to be the same as Key Id in JWT signing key.
      The value can be updated if necessary.
5. Create API Access Policy or add Authentication profile to existing Policy by accessing: All→System Web Services→API Access Policies→Rest API Access Policies

**IMPORTANT:**
1. The Standard Authentication Profile of type Oauth should be already present in ServiceNow and has to be added to the Policy.
API Access Policy should be configured as global in order to cover all available resources and not just now/table
2. Granting JWT to admin is not allowed.
You should have a non-admin user with all necessary roles (only non-admin roles) in addition to the existing role snc_platform_rest_api_access that is required to make API calls.

### Using Multi Factor Authentication (MFA)
MFA can be used both when using basic authorization and when using OAuth 2.0 authorization, however, we strongly recommend using OAuth 2.0 when using MFA.
If MFA is enabled for your user, perform the following steps:
1. Open the Google Authenticator application on your mobile device and make note of the number. The number refreshes every 30 seconds.
2. Enter your username and password, and append the One Time Password (OTP) that you currently see on your mobile device to your password without any extra spaces. For example, if your password is **12345** and the current OTP code is **424 058**, enter `12345424058`.

**Notes:**
1. When using basic authorization, you will have to update your password with the current OTP every time the current code expires (30 seconds), therefore we recommend using OAuth 2.0 authorization.
2. For using OAuth 2.0 see the instructions above. The OTP code should be appended to the password parameter in the ***!servicenow-cmdb-oauth-login*** command.
