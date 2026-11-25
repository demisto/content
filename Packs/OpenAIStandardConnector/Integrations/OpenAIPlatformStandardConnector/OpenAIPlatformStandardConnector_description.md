## OpenAI API Platform

This integration is configured automatically by the **OpenAI** standard connector (service **OpenAI API Platform**). Set it up from the connector page.

Each capability uses its own credential, and you can enable either one alone:

| Capability | Credential | Required role |
| --- | --- | --- |
| Automation and Remediation (GPT commands) | OpenAI API Key | A project member. A project-scoped key (or a service account key) is recommended. |
| Log Collection (OpenAI Audit logs) | Admin API Key | Organization Owner. Audit logging must be enabled. |

### Automation and Remediation - OpenAI API Key

1. Sign in to [https://platform.openai.com](https://platform.openai.com).
2. Generate a project API key at [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys). See [API keys](https://developers.openai.com/api/docs/guides/api-keys).

The GPT commands use the Chat Completions, Responses, Models and Moderations endpoints on `https://api.openai.com`. Set **Model** to a model ID from the [OpenAI models page](https://developers.openai.com/api/docs/models) (or run `gpt-list-models`). Before each GPT command runs, the model is checked against the models available to the API Key. Each model has its own rate limit: see [rate limits](https://platform.openai.com/docs/guides/rate-limits).

### Log Collection - Admin API Key (OpenAI Audit logs)

- Only **Organization Owners** can create and use Admin API keys: <https://platform.openai.com/settings/organization/admin-keys>
- Audit logging must be enabled from **Organization settings > Data controls > Data retention**. Once enabled it **cannot be self-disabled**. See OpenAI's [Audit logging documentation](https://platform.openai.com/docs/guides/audit-logs).

Audit events are ingested into the `openai_admin_audit_raw` dataset.

### Verify

**Verify** tests only the credentials of the capabilities you enabled: the OpenAI API Key against the Models endpoint (no model is called, so the selected model does not affect Verify), and the Admin API Key against the Audit logs endpoint. An authorization error names the key to fix.

### Moving from the OpenAI GPT integration

Existing **OpenAI GPT** instances keep working and are not changed. The commands, arguments, outputs and datasets are the same in this connector. A guided migration of existing instances is planned for a later release. Until then, if you set up this connector for an organization that an existing OpenAI GPT instance already collects from, disable collection on one of them, because both write to the same datasets.
