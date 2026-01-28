BeyondTrust Privilege Management Cloud (PM Cloud) integration for retrieving audit events and activity logs.

## Create a Token

Create a token by POSTing to the URL of your BeyondTrust site followed by `/oauth/connect/token`:

`https://example-services.pm.beyondtrustcloud.com/oauth/connect/token`

**NOTE:** Replace "example" with your production sub-domain name, as shown:

`https://[yourProductionSub-domainName]-services.pm.beyondtrustcloud.com/oauth/connect/token`

The OAuth client ID and client secret associated with the API account should be included in the POST body:

`grant_type=client_credentials&client_id=[yourClientId]&client_secret=[yourGeneratedClientSecret]`

Send the POST request using an HTTP client. Ensure the Content-Type header is set to `application/x-www-form-urlencoded`.

If the request is processed without error, you will get an access token JSON response:

```json
{
    "access_token":"<token>",
    "token_type":"Bearer",
    "expires_in":3600,
    "Scope":"urn:management:api"
}
```
