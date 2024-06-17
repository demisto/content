## Thales CipherTrust Manager Integration

Use the Thales CipherTrust Manager integration to manage secrets and protect sensitive data through Thales CipherTrust Manager.


### Configuration Notes - Authenticating to Thales CipherTrust Manager

The Thales CipherTrust Manager integration utilizes the Thales CipherTrust Manager REST API to communicate with the Thales CipherTrust Manager server. The REST API is hosted at the following base URL: `{Server URL}/api/v1`.
The integration employs API token generation for user credentials by accessing the `/auth/tokens/` endpoint with the 'password' grant-type. This endpoint allows the exchange of a username and password for an access token for the root domain.

### Main Use Cases for the Thales CipherTrust Manager Integration

The Thales CipherTrust Manager integration supports several key use cases:

#### 1. Groups Management
#### 2. Users Management
#### 3. Certificate Authority


