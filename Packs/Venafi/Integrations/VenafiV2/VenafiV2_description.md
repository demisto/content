To access the Venafi TLS Protect service, you need to provide:

- Your Venafi TLS Protect server URL. For example: "https://example.ven-eco.com".
- The Client ID, username, and password as parameters for the integration.

### OAuth 2.0
#### Setting up token authentication
1. From the Platform product menu, click API > Default Settings.
2. Expand the Tokens panel, and confirm or update the following values as appropriate:

| Field                      | Description                                                                                                                                                                                                                                                                                                                                                                                                                |
| -------------------------- |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Refresh Token              | Refresh settings:<br>- Enabled: Default. Receive a refresh token with the request for a bearer access token. Prior to the Token Validity day, you can send the refresh token to the VEDAuth server to get a new bearer access token.<br>- Disabled: At the time when the VEDAuth server issues a bearer access token, no refresh token is supplied. The validity period is determined by the application's grant validity. |
| Token expires after        | The period of time that the bearer access token is valid before rotation is required. The default is 90 days.                                                                                                                                                                                                                                                                                                              |
| Access expires after       | The maximum time that an authorization grant for the Token Auth scope is valid. If the Refresh Token is enabled, you can continue to get new tokens until the token and grant expire. The default is 1 year.                                                                                                                                                                                                               |

3. Expand the Session cache panel and confirm or update the following values as appropriate.

| Field                        | Description                                                                                                                                                                                                                                                                               |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Expiration Mode              | Expiration mode settings:<br>- Normal: (Default) Credentials will be cached for better performance. Cache will refresh with the Session expiration setting, described below.<br>- Strict: Credentials will be verified on every API call, requiring an extra call to the database for every call, thus costing performance. (Internal testing at Venafi suggests response time can be 40% longer when using Strict mode.) |
| Session Pool Size (sessions) | The number of concurrent sessions for API calls. The default is 5000. If the number of simultaneous API calls exceed the pool size, the oldest unused session is removed from the pool.                                                                                                                                                         |
| Session Expiration (minutes)| The number of minutes each token remains in memory. The default is 1440, which is 24 hours.                                                                                                                                                                                             |

4. Allowed Authentication Methods

| Authentication                           | Trust Protection Platform Authentication Server Setting                                                                                                                                                                                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Username & Password                      | The client passes a user name and password to the VEDAuth server                                                                                                                                                                                                                                |
| Integrated MS Windows Authentication     | Default. The client passes Windows credentials to the VEDAuth server                                                                                                                                                                                                                            |
| Browser-based authentication             | - Enabled: Default. Allow multi-factor authentication for devices. A successful response includes a web link to complete the authentication.<br>- Disabled: Block browser-based authentication                                                                                                                                                   |
| JSON web token                           | A token in JSON format that is used to communicate between a trusted identity provider and Venafi Platform                                                                                                                                                                                     |
| Certificate                              | The caller passes a client certificate to the VEDAuth server. When selected, the Use AD Security Identifier (SID) value if available option appears                                                                                                                                              |
| AD Security Identifier (SID)            | If you select Certificate, the Use AD Security Identifier (SID) value if available option appears. In this scenario, AuthServer follows a specific process. First, it looks for the SID Extension value in the certificate. If the SID Extension is found, AuthServer tries to find the matching AD user. However, if the SID Extension is not in the certificate or doesn't match an AD account, AuthServer will then use the "Location" setting as a backup. |

5. Click Save
6. Either wait 10 minutes or remote into the server and from the command line, type iisreset.
7. Find the scopes that your application needs in the [Scope map for tokens.](https://docs.venafi.com/Docs/23.3/TopNav/Content/SDK/AuthSDK/r-SDKa-OAuthScopePrivilegeMapping.php)
8. From the Platform menu bar, click API > Integrations, register and set scopes for your application. 

Set all of the scopes that your integration requires.
```
{
"username": "<your_username>",
"password": "<your_password",
"client_id": "My Certificate Integration",
"scope": "certificate"
}
```

#### Getting a token
To get a token, call an Authorize method with the values you just defined. For more information, see [Getting a token.](https://docs.venafi.com/Docs/23.3/TopNav/Content/SDK/AuthSDK/t-SDKa-GetBearerToken.php)

