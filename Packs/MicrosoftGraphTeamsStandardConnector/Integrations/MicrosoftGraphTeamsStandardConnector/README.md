## Overview

Satellite integration of the community **O365 Teams (Using Graph API)** pack, wired for the **Microsoft 365** Standard Connector. Exposes one command: `msgraph-teams-message-update-policy-violation` for applying Microsoft Graph DLP policyViolation on Teams messages.

**Do not configure this integration directly.** It is configured automatically as part of the Microsoft 365 Standard Connector — set it up from the connector page.

## Configuration

All configuration is injected by the Unified Connector Platform (UCP) from the connector page. The parameter names are:

| Parameter | Description |
| --- | --- |
| `url` | Microsoft Graph server URL. Defaults to `https://graph.microsoft.com`; the connector does not push this value, so the default is used at runtime. |
| `tenant_id` | Microsoft Entra tenant ID. |
| `client_id` | Application (client) ID of the Microsoft Entra application. |
| `secret` | Client secret of the Microsoft Entra application. Delivered as `client_secret` by the connector and remapped by the connector-side serializer. |
| `insecure` | Trust any certificate (not secure). |
| `proxy` | Use system proxy settings. |

## Commands

### msgraph-teams-message-update-policy-violation

Applies a DLP `policyViolation` to a Microsoft Teams message. Targets a chat message, a channel message, or a channel reply — provide either `chat_id`, or both `team_id` and `channel_id`. `parent_message_id` is only valid for channel-message replies.
