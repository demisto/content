## Cloudflare Server

Select the Cloudflare MCP server you want to connect to.
For more information about the tools available in each server, see [Cloudflare MCP Server](https://github.com/cloudflare/mcp-server-cloudflare#cloudflare-mcp-server).

## Authorization code

**Note:** Authentication is not required for the `docs` server.

To obtain the Authorization code, follow these steps:

1. Save the integration instance.
2. Run the integration command `!cloudflare-mcp-generate-login-url`from the Playground and follow its instructions.
3. Copy the generated Authorization code into the integration instance and save the integration instance.
4. Run the integration command `!cloudflare-mcp-auth-test` from the Playground to verify that everything is configured correctly.

## Redirect URI

The default Redirect URI is `https://oproxy.demisto.ninja/authcode`.
You can change this parameter to any valid URI you prefer.
**Important:** You must add the configured Redirect URI (whether default or custom) to the allowed list in your Cloudflare application settings.
