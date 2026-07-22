## Thales CipherTrust Manager Integration

Use the Thales CipherTrust Manager integration to manage secrets and protect sensitive data through Thales CipherTrust Manager.


### Configuration Notes - Authenticating to Thales CipherTrust Manager

The Thales CipherTrust Manager integration utilizes the Thales CipherTrust Manager REST API to communicate with the Thales CipherTrust Manager server. The REST API is hosted at the following base URL: `{Server URL}/api/v1`.
The integration employs API token generation for user credentials by accessing the `/auth/tokens/` endpoint with the 'password' grant-type. This endpoint allows the exchange of a username and password for an access token for the root domain.

### Permissions

For details on the Attribute-based Access Control (ABAC) permissions required for operations on resources, see the [CipherTrust Documentation](https://thalesdocs.com/ctp/cm/latest/admin/cm_admin/abac-permissions/index.html).

