To generate a token for the *Token* parameter:

1. Log in to your Symantec Endpoint Security console.
2. Click **Integration** > **Client Applications**.
3. Choose `Add Client Application`.
4. Choose a name for the application, then click `Add`. The client application details screen will appear.
5. Click `⋮` and select `Client Secret`.
6. Click the ellipsis and select **Client Secret**.
7. Click the `copy` icon next to `OAuth Credentials`.
8. Paste the OAuth Credentials value into the `Token` field.

for more information about to obtain the *Token* see [here](https://apidocs.securitycloud.symantec.com/#/doc?id=ses_auth)

**Note: There’s no need to generate the bearer token, the integration uses the provided token to generate one.**
