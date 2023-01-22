## RunZero Integration Help

### Generate API tokens
To get started, you will need an API key / token or API client credentials.
Export API tokens and Organization API keys can be generated 
by going to the Organizations section in the runZero web console,
clicking on the appropriate organization name, and scrolling down to the export
tokens or API tokens section. 
A button there will let you generate a secure API key, in the form
of a long random token. You must have administrator access to generate API keys.

### API Limit
API calls are rate limited.
You can make as many API calls per day as you have licensed assets in your account.
For example, if you have 1,000 licensed assets, you can make 1,000 API calls
per day. 
Each API call returns rate limit information in the HTTP headers of the response:
X-API-Usage-Total - Total number of calls made to the API
X-API-Usage-Today - Number of calls made to the API today
X-API-Usage-Limit - Your daily API call limit, shared across all API keys
X-API-Usage-Remaining - The number of API calls remaining from your daily limit
Please see the Swagger documentation and runZero OpenAPI specification for details on the
individual API calls.