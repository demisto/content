## OpenAI

### Generate an API Key

1. Sign-up or login to [https://platform.openai.com](https://platform.openai.com).
2. Generate a new API Key at [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys).

### Models & Rate Limits

The integration utilizes the **'Chat Completions'** endpoint merely. Therefore, it will only be possible to configure models that support the following endpoint: _https://api.openai.com/v1/chat/completions_.

_For many basic tasks, the difference between GPT-4 and GPT-3.5 models is not significant. However, in more complex reasoning situations, GPT-4 is much more capable than any of our previous models._

For tasks requiring deep understanding and extensive inputs, opt for more advanced models (e.g. gpt-4). These models offer a larger context window, allowing them to process bigger documents, and provide more refined and comprehensive responses.
The more elementary models (e.g. gpt-3.5) often provide shallower answers with a smaller input tokens' limit, but are less costly.

- [Models overview](https://platform.openai.com/docs/models/overview)

- Each model has its own requests' rate-limit: Refer to [rate-limits](https://platform.openai.com/docs/guides/rate-limits).

### How to use this integration with XSOAR

#### The following blog post ['Palo Alto Networks - Playbook of the week'](https://www.paloaltonetworks.com/blog/security-operations/using-chatgpt-in-cortex-xsoar/) by Sam Testov explains how to use this integration in your playbooks:

<~XSIAM>

---

## ChatGPT

### Event Collector Setup

The OpenAI integration can collect **Audit logs** (OpenAI Admin API) and **Compliance logs** (ChatGPT Platform) and forward them to Cortex as events. This section covers the prerequisites for both feeds. For full background, see the [design document](https://docs.google.com/document/d/1AQdeSL4RZya19ZVtnBJK-hIk8wBUElIahF4NlZ9nti8/edit?tab=t.0).

#### Setting up your organization

After signing in to your OpenAI account, your organization name and ID are listed under **Organization settings**. The organization name is the human-readable label; the organization ID is the unique identifier used in API requests.

If your account belongs to multiple organizations, you can pass an `OpenAI-Organization` header to scope an API request to a specific organization. Usage from those requests counts against that organization's quota. If the header is omitted, the default organization is billed. The default organization can be changed in your user settings.

- Create an Admin key: <https://platform.openai.com/settings/organization/admin-keys>
- Enable Audit logging: <https://platform.openai.com/settings/organization/data-controls/data-retention>

#### Enable Audit logging for the organization

> **Important**: Once Audit logging is enabled for an API Platform organization it **cannot be self-disabled**. Only Organization Owners can contact OpenAI support to disable it afterwards.

Organization Owners enable Audit logging from **Organization settings → Data controls → Data retention**, then toggle **Enable** under **Audit logging** at the bottom of the page and save. Once saved, Audit logging is active for the organization. See OpenAI's [Audit logging documentation](https://platform.openai.com/docs/guides/audit-logs) for the full reference.

#### Who can use Audit log API keys?

Only **Organization Owners** can create and use Admin API keys for the purpose of pulling Audit Logs. Audit logging must be enabled (see the previous step) before the Admin API will return any data.

#### Authentication for the Compliance Logs Platform

Owners generate the Compliance API key in the **OpenAI API Platform Portal**. Make sure the **correct Organization** is selected when creating the key — it must correspond to the workspace being administered. **Do not select the owner's personal organization.**

When creating the key, use:

- **Settings**: _Default Project_ | _All Permissions_

A few important constraints:

- This must be a **new** key. Once Compliance API scopes are granted to it, all other scopes on the key are revoked.
- The key value can only be **viewed/copied once at creation time** — store it securely.

To enable Compliance API access on the key:

1. Email **[support@openai.com](mailto:support@openai.com)** with:
   - The **last 4 digits** of the API key.
   - The **Key Name**.
   - The **Created By** name.
   - The **requested scope** (`read`, `delete`, or both).
2. OpenAI's team will verify the key and grant the requested Compliance API scopes.
3. Once the key has Compliance scopes, administrators can use it directly or hand it to a partner for use against the Compliance API.

Use `https://api.chatgpt.com/v1/` as the base URL for all Compliance API endpoints.

</~XSIAM>
