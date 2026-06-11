# Darkmon Feed

Darkmon TIP indicator feed for Cortex XSOAR. Pulls IPs, URLs, domains,
file hashes, emails, and accounts from the Darkmon Threat Intel firehose
into the XSOAR TIM module.

This integration is the **feed half** of the Darkmon pack. For the
incident-side functionality (incident fetching, dynamic search, reputation
commands, monitoring playbooks), use the companion **Darkmon** integration
in the same pack.

## Commands

### `darkmon-get-indicators`

Fetch a page of Darkmon indicators on demand without waiting for the
next scheduled feed cycle. Useful for verifying connectivity and
indicator shape during integration setup.

| Argument | Description | Default |
|---|---|---|
| `limit` | Maximum indicators to return | 20 |

#### Context output

| Path | Description | Type |
|---|---|---|
| `Darkmon.Indicator.value` | Indicator value | String |
| `Darkmon.Indicator.type` | Indicator type (IP / Domain / URL / Email / File / Account) | String |
| `Darkmon.Indicator.classification` | Darkmon's classification for the indicator | String |
| `Darkmon.Indicator.timestamp` | First-seen-by-Darkmon timestamp | Date |
