Gets failed tasks details for incidents based on a query. Limited to 1000 incidents

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/playbooks/automations.html
](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/playbooks/automations.html)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Integrations and Playbooks Health Check - Running Scripts

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | The query by which to retrieve failed tasks. Optional. The default value is "-status:closed" |
| tenant_name | The tenant name. |
| max_incidents | Maximum number of incidents to query. Maximum is 1000. |

## Outputs
---
There are no outputs for this script.

## Troubleshooting
In order for the automation script to be able to retrieve the failed tasks, the API key configured in the Demisto REST API integration, need to be of a user with *Read* permissions to the queried incident.