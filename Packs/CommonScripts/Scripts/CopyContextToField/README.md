Copy a context key to an incident field of multiple incidents, based on an incident query.

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations)

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
