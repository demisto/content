## ChatGPT Workspace

This integration is configured automatically by the **OpenAI** standard connector (service **ChatGPT Workspace**). Set it up from the connector page.

This service offers **Log Collection** only (ChatGPT Compliance logs). It uses one credential, the Compliance API Key, plus the Workspace ID. It does not need the OpenAI API Platform keys.

### Log Collection - Compliance API Key (ChatGPT Compliance logs)

Required role: a ChatGPT workspace Owner (Enterprise or Edu workspace with Compliance API access). See [Managing Admin keys](https://help.openai.com/en/articles/20001407-managing-admin-keys-in-admin-console).

Owners generate the Compliance API key in the **OpenAI API Platform Portal**. Select the organization that corresponds to the workspace being administered, not the owner's personal organization. Create the key with **Default Project** and **All Permissions**.

- It must be a **new** key. Once Compliance API scopes are granted, all other scopes on the key are revoked.
- The key value can only be viewed once, at creation time.

To enable Compliance API access, email **[support@openai.com](mailto:support@openai.com)** with the last 4 digits of the key, the key name, the creator name and the requested scope (`read`). OpenAI then grants the Compliance scopes.

### Workspace ID

The Compliance workspace UUID (for example, `4a4676f3-3d74-4723-b696-c93e6d01078a`). It is required to fetch Compliance events.

Compliance events are ingested into the `openai_chatgpt_compliance_raw` dataset. The Compliance API base URL is `https://api.chatgpt.com`.

### Verify

**Verify** tests the Compliance API Key and Workspace ID against the Compliance logs endpoint for each selected event type.

### Moving from the OpenAI GPT integration

Existing **OpenAI GPT** instances keep working and are not changed. The event types and the dataset are the same in this connector. A guided migration of existing instances is planned for a later release. Until then, if you set up this connector for a workspace that an existing OpenAI GPT instance already collects from, disable Compliance collection on one of them, because both write to the same dataset.
