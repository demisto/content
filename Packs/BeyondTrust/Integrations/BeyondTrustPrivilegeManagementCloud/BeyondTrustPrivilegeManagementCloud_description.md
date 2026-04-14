BeyondTrust Privilege Management Cloud (PM Cloud) integration for retrieving audit events and activity logs.

## Authenticate to the API

To authenticate to the API, you must create an API account on the **Configuration > Settings > API Settings** page. The account must have permission to access the necessary APIs. API requests require a token to be first created and then submitted with each API request.

## Important Information

The instance URL to use with the EPM API can be found at the top of the **API Settings** page:

- In **Pathfinder**: Endpoint Privilege Management for Windows and Mac > Configuration > API Settings
- In **Classic**: Configuration > API Settings

**Note:** The client secret cannot be modified, but it can be regenerated on the **Configuration > Settings > API Settings** page. Regenerating a client secret and then saving the account immediately invalidates any OAuth tokens associated with the account. Any API calls using those tokens will be unable to access the API. A new token must be generated using the new client secret.
