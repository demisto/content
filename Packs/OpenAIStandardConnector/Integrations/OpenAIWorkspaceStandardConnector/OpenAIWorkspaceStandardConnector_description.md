## ChatGPT Workspace

This integration is configured automatically by the **OpenAI** standard connector (service **ChatGPT Workspace**). Set it up from the connector page.

### Log Collection - Compliance API Key (ChatGPT Compliance logs)

Owners generate the Compliance API key in the **OpenAI API Platform Portal**. Select the organization that corresponds to the workspace being administered, not the owner's personal organization. Create the key with **Default Project** and **All Permissions**.

- It must be a **new** key. Once Compliance API scopes are granted, all other scopes on the key are revoked.
- The key value can only be viewed once, at creation time.

To enable Compliance API access, email **[support@openai.com](mailto:support@openai.com)** with the last 4 digits of the key, the key name, the creator name and the requested scope (`read`). OpenAI then grants the Compliance scopes.

### Workspace ID

The Compliance workspace UUID (for example, `4a4676f3-3d74-4723-b696-c93e6d01078a`). It is required to fetch Compliance events.

Compliance events are ingested into the `openai_chatgpt_compliance_raw` dataset. The Compliance API base URL is `https://api.chatgpt.com`.
