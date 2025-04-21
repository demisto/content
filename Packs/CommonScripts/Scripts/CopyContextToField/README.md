Copy a context key to an incident field of multiple incidents, based on an incident query.

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| sourceContextKey | The context key from which to get the value. |
| targetIncidentField | The incident field to set with the value. |
| incidentsQuery | The incidents query on which to apply the copy process. For example, to apply this to all incidents of type "Phishing", use the query: "type:Phishing". |
| limit | The maximum number of incidents to edit. Default is 1,000. |
| listSeparator | Concatenates list values. |

## Outputs
---
There are no outputs for this script.
