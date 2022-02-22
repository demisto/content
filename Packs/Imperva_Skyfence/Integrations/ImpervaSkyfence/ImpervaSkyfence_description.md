To use the Imperva Skyfence integration, you need to retrieve your credentials, and generate an authentication to use for all requests.

## Get your credentials
In the Skyfence platform, the customer ID is the "Client ID", and the password is the "Client Secret".
- To obtain these credentials, go to the Skyfence platform and navigate to **Settings > API**.

## Generate an authentication token
All API requests require authentication. The authentication model is OAuth 2.0, which requires an authentication token. To receive an authentication token, the client performs
a token request by providing a customer ID and password. The received token is used in all requests.

Important/:/ The Client Secret is displayed only during the initial use. Make sure you copy the Client Secret for further reference.