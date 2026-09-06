## Anthropic Claude


### Generate an API Key
1. Sign-up or login to [https://console.anthropic.com](https://console.anthropic.com).
2. Generate a new API Key at [https://console.anthropic.com/keys](https://console.anthropic.com/keys).

### Models & Rate Limits
The integration utilizes the **'Messages'** endpoint. Therefore, it will only be possible to configure models that support the following endpoint: _https://api.anthropic.com/v1/messages_.

_Claude models offer different capabilities, with more advanced models providing better reasoning and comprehension capabilities._

For tasks requiring deep understanding and extensive inputs, opt for more advanced models (e.g. claude-3-opus). These models offer a larger context window, allowing them to process bigger documents, and provide more refined and comprehensive responses.
The more basic models (e.g. claude-3-haiku) often provide simpler answers but are faster and less costly.
- [Models overview](https://docs.anthropic.com/claude/docs/models-overview)

- Each model has its own rate limits: Refer to [rate-limits](https://docs.anthropic.com/claude/reference/rate-limits).


### How to use this integration with XSIAM
This integration allows you to:
- Send messages to Claude models and receive AI-generated responses
- Analyze email headers and bodies for security threats
- Generate SOC email templates
- Collect Anthropic Compliance API Activity Feed events into Cortex XSIAM
- Enumerate the directory (organizations, users, roles, groups) and retrieve content metadata (chats, files, projects)

### Credentials
This integration supports two independent credentials; configure either or both:
- **API Key** — required for the LLM commands (`claude-send-message`, `claude-check-email-*`, `claude-create-soc-email-template`). Generate one at [https://console.anthropic.com/keys](https://console.anthropic.com/keys).
- **Compliance Access Key** (`sk-ant-api01-...`) — required for event collection and the read-only `claude-list-*` / `claude-get-*` commands.

### Compliance API
Event collection and the read-only compliance commands use the **Compliance Access Key**.

#### Prerequisites
The Compliance API is enabled on request (Claude Enterprise plan for the full API). An org owner creates a Compliance Access Key in claude.ai with scopes `read:compliance_activities`, `read:compliance_org_data`, and `read:compliance_user_data`.

See [how to create a Compliance API Key](https://platform.claude.com/docs/en/manage-claude/compliance-api-access).

To enable event collection, set the Compliance Access Key and select **Fetch events**. The first fetch collects the last minute of activity; subsequent fetches continue from the last collected event.

You can optionally set a default **Organization UUID** that the compliance commands fall back to when their `org_uuid` argument is not provided. Use the **Activity types** parameter (a comma-separated list) to narrow the Activity Feed; see the available types in the [Compliance API documentation](https://platform.claude.com/docs/en/api/compliance/activities/list).

---