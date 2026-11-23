## Anthropic Claude Standard Connector

This integration is configured automatically as part of the **Claude** connector. Do not configure this integration directly. Set it up from the connector page instead.

- **Compliance actions** and **Log Collection** use the Anthropic Compliance Access Key (`sk-ant-api01-...`). The delete commands also require the `delete:compliance_user_data` scope.
- **Claude model commands** use an Anthropic Messages API key. Generate one at https://platform.claude.com/settings/keys.
- **First fetch time** sets where log collection starts. When you move from another Anthropic Claude instance, set it to that instance's last fetch time to avoid gaps or duplicate events.
