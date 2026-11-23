## Command Zero MCP

### Create a Command Zero API key

1. In the Command Zero console, select **Settings** from the left menu.
2. In the Settings menu, select **Applications (API Keys)**.
3. Click **New Application**.
4. Enter a name (for example, "Palo Alto Key"), select a role, and select an expiry date or select the **No expiry** checkbox.
5. Click **Create**.
6. Copy the key value and store it in a safe location.

The integration can perform only the actions allowed by the API key's role. The Observer role may be used for read-only access. We recommend using the Investigator role for creation of new investigations and to ask questions.

### Configure the integration

1. Select the Region that hosts your Command Zero organization.
2. Enter your Command Zero API key.
3. If the API key has access to more than one organization, enter the ID of the Command Zero organization to connect to.
4. Click **Test** to verify that everything is configured correctly.
