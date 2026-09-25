To obtain the Authorization code, follow these steps:

1. Select the Region that hosts your Command Zero organization and save the integration instance.
2. Run the integration command `!command-zero-mcp-generate-login-url` from the Playground and follow its instructions.
3. Sign in to Command Zero and select the organization and role for this connection. The integration can perform only the actions allowed by the selected role.
4. Copy the generated Authorization code into the integration instance and save the integration instance.
5. Run the integration command `!command-zero-mcp-auth-test` from the Playground to verify that everything is configured correctly.

The Authorization code expires two minutes after you sign in and can be used only once. If it expires, or if `!command-zero-mcp-auth-test` reports that no login session was found, repeat the steps above to generate a new login URL.

We recommend authorizing with a dedicated Command Zero service account, and selecting the Observer role for read-only access.