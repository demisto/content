## Thales CipherTrust Manager Integration

Use the Thales CipherTrust Manager integration to manage secrets and protect sensitive data through Thales CipherTrust Manager.

### Overview

CipherTrust Manager enables key lifecycle management tasks. It enables organizations to centrally manage encryption keys for the Thales CipherTrust Data Security Platform and third-party products. Role-based access provides control to keys and policies and reporting of all key management and encryption operations.

### Configuration Notes - Authenticating to Thales CipherTrust Manager

The Thales CipherTrust Manager integration utilizes the Thales CipherTrust Manager REST API to communicate with the Thales CipherTrust Manager server. The REST API is hosted at the following base URL: `{Server URL}/api/v1`.

API calls are authenticated using access tokens. An access token is a string representing an authorization issued to the client, often referred to as an API authentication token. Access tokens expire and so must be refreshed periodically. A new access token is created with the user's credentials upon each command.

#### Token Generation

The integration employs API token generation for user credentials by accessing the `/auth/tokens/` endpoint with the 'password' grant-type. This endpoint allows the exchange of a username and password for an access token for the root domain.

### Main Use Cases for the Thales CipherTrust Manager Integration

The Thales CipherTrust Manager integration supports several key use cases:

#### 1. Groups Management
#### 2. Users Management
#### 3. Certificate Authority


