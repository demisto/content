### Authentication

In the Atlassian Standard Connector this integration authenticates with an **API key**
connection profile: the user provisioning (SCIM) directory API key of your Atlassian
organization. The key is sent on every request as `Authorization: Bearer <key>`.

To create the key, from your organization at admin.atlassian.com:
1. Go to **Security** > **User provisioning** (or **Settings** > **API keys**).
2. Create a directory / API key and copy the **Directory base URL**, **Directory ID** and
   **API key**. Keys expire (one week by default, at most one year).

Set **Atlassian URL** to `https://api.atlassian.com` and **Directory ID** to the SCIM
directory ID.

### Enable/Disable CRUD Commands
You can select which CRUD commands are enabled in the integration instance configuration
settings. By default, all commands are enabled.

### Automatically create user if not found in update command
The *create-if-not-exists* parameter specifies if a new user should be created when the
User Profile passed was not found in Atlassian.
