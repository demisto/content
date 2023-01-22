## RunZero Event Collector Help
Use this integration to collect events automatically from RunZero.
You can also use the ***runzero-get-events*** command to manually collect events.

### API Key
Account API keys are generated from the Account settings page. Note that the Account API
requires an Enterprise license.
Account API client credentials are managed from the API clients page. Your REST client should
use the OAuth 2.0 authorization type and Client Credentials grant type. See the OpenAPI
specification for the access token details. Use the client ID and client secret to generate an
access token as shown in the following example: curl -X POST -H "Content-Type:
application/x-www-form-urlencoded" -d
"grant_type=client_credentials&client_id=<CLIENT_ID>&client_secret=
<CLIENT_SECRET>" https://console.runzero.com/api/v1.0/account/api/token
Once you have generated an API key or access token, your REST client should use it with the
Authorization: Bearer standard header to authenticate.
To use an Account API key or token with the Organization or Export API, specify the additional
parameter _oid=[organization-id] in the query parameters.

### API Limit
API calls are rate limited. You can make as many API calls per day as you have licensed assets
in your account. For example, if you have 1,000 licensed assets, you can make 1,000 API calls
per day. Each API call returns rate limit information in the HTTP headers of the response:
X-API-Usage-Total - Total number of calls made to the API
X-API-Usage-Today - Number of calls made to the API today
X-API-Usage-Limit - Your daily API call limit, shared across all API keys
X-API-Usage-Remaining - The number of API calls remaining from your daily limit
Please see the Swagger documentation and runZero OpenAPI specification for details on the
individual API calls.
