## Generic MCP Integration Description

This integration allows you to connect securely with any MCP server and access its tools in real time.

### Configuration para

1. **Server URL**: The base URL of the MCP server. This is a required parameter for all authentication types.

2. **Authentication Type**: Select the authentication method to use for connecting to the MCP server.

    * **Basic**: Uses a username and password for authentication.
        * **Username & Password**: Provide the username and password for basic authentication.

    * **Token**: Uses a single API token or key for authentication.
        * **API Token / API Key**: Provide the API Token or API Key to access the service REST API.

    * **Bearer**: Uses a Bearer token for authentication.
        * **API Token / API Key**: Provide the Bearer Token to access the service REST API.

    * **Api-Key**: Uses an API key for authentication.
        * **API Token / API Key**: Provide the API Key to access the service REST API.

    * **RawToken**: Uses a raw token for authentication.
        * **API Token / API Key**: Provide the raw token to access the service REST API.

    * **OAuth 2.0 Authorization Code**: Uses the OAuth 2.0 Authorization Code flow for authentication.
        * **Client ID**: The Client ID for your application.
        * **Client Secret**: The Client Secret for your application.
        * **Authorization code**: Required to obtain the access token. To get this code, run the `generic-mcp-generate-login-url` command and follow its instructions.
        * **Scope**: Space-separated permission identifiers requested from the authorization server.

    * **OAuth 2.0 Client Credentials**: Uses the OAuth 2.0 Client Credentials flow for authentication.
        * **Client ID**: The Client ID for your application.
        * **Client Secret**: The Client Secret for your application.
        * **Scope**: Space-separated permission identifiers requested from the authorization server.

    * **OAuth 2.0 Dynamic Client Registration**: Uses OAuth 2.0 Dynamic Client Registration.
        * **Authorization code**: Required to obtain the access token. To get this code, run the `generic-mcp-generate-login-url` command and follow its instructions.
        * **Scope**: Space-separated permission identifiers requested from the authorization server.

    * **No Authorization**: No authentication is used.

### Advanced Parameters

* **Redirect URI**: The URI to which the authorization server redirects the user-agent after granting authorization. This is typically used in OAuth 2.0 Authorization Code flow. Default: `https://oproxy.demisto.ninja/authcode`.
* **Custom headers**: Add custom headers to be sent with each API request. Enter each header on a new line in the format: `HeaderName: HeaderValue`.
* **Authorization Endpoint**: The URL for the OAuth 2.0 authorization endpoint. If not provided, the default will be the origin of the `base_url` followed by `/oauth2/authorize`. For example, if `base_url` is `https://example.com/mcp`, the default `Authorization Endpoint` will be `https://example.com/oauth2/authorize`.
* **Token Endpoint**: The URL for the OAuth 2.0 token endpoint. If not provided, the default will be the origin of the `base_url` followed by `/oauth2/token`. For example, if `base_url` is `https://example.com/mcp`, the default `Token Endpoint` will be `https://example.com/oauth2/token`.
* **Trust any certificate (not secure)**: Select this option to trust any certificate. This is not recommended for production environments.
