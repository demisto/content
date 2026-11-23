## OpenAI API Platform

This integration is configured automatically by the **OpenAI** standard connector (service **OpenAI API Platform**). Set it up from the connector page.

### Automation and Remediation - OpenAI API Key

1. Sign in to [https://platform.openai.com](https://platform.openai.com).
2. Generate an API key at [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys).

The GPT commands use the Chat Completions, Responses, Models and Moderations endpoints on `https://api.openai.com`. Each model has its own rate limit: see [rate limits](https://platform.openai.com/docs/guides/rate-limits).

### Log Collection - Admin API Key (OpenAI Audit logs)

- Only **Organization Owners** can create and use Admin API keys: <https://platform.openai.com/settings/organization/admin-keys>
- Audit logging must be enabled from **Organization settings > Data controls > Data retention**. Once enabled it **cannot be self-disabled**. See OpenAI's [Audit logging documentation](https://platform.openai.com/docs/guides/audit-logs).

Audit events are ingested into the `openai_admin_audit_raw` dataset.

### Organization ID

Your organization ID (`org-...`) is listed under **Organization settings**. When set, it is sent as the `OpenAI-Organization` header so requests are scoped to that organization.
