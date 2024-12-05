Creates a channel in Slack v2 or in Microsoft Teams. If both Slack v2 and Microsoft Teams are available, it creates the channel in both Slack v2 and Microsoft Teams.

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Shift Management, ooo |
| Cortex XSOAR Version | 5.5.0 |

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
