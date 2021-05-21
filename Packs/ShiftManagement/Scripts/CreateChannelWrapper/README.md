Creates a channel in Slack v2 or in Microsoft Teams. If both Slack v2 and Microsoft Teams are available, it creates the channel in both Slack v2 and Microsoft Teams.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Shift Management, ooo |
| Demisto Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| name | The name of the channel. |
| type | The channel type. Can be "private" or "public".  Relevant only for Slack. |
| team | The team in which to create the channel. Relevant only for Microsoft Teams. |
| description | The description of the channel. Relevant only for Microsoft Teams. |

## Outputs
---
There are no outputs for this script.
