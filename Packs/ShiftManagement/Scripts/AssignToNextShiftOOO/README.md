Randomly assigns the active incidents to on-call analysts (requires shift management). This automation works with the other out-of-office automations to ensure only available analysts are assigned to the active incidents. 

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
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
Assign Active Incidents to Next Shift V2

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incidentIds | A comma-separated list of active incident IDs to assign to the next shift, for example, 1,2,3,4. |
| listname | The name of the out-of-office list. Default is "OOO List". |

## Outputs
---
There are no outputs for this script.
