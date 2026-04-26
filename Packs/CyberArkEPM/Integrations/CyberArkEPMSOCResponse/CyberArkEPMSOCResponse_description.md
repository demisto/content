## CyberArk EPM

### Authentication
To authenticate to EPM with OAuth2, provide the following:

- tenant_url: The tenant URL for EPM region (e.g., https://api-na.epm.cyberark.cloud)
- token_url: The CyberArk Identity FQDN for OAuth2 authentication (e.g., https://abc1234.id.cyberark.cloud)
- web_app_id: The Application ID of the OAuth2 Server web app configured in Identity Administration.
- client_id: Service username (configured as OAuth confidential client).
- client_secret: Service user password for OAuth2 authentication.

### Endpoint Information

To specify an endpoint, use the following command arguments: 
- `endpoint_name`
- `endpoint_external_ip`
- In addition, provide a pre-defined risk plan (for example, `Medium_Risk_Plan`).


