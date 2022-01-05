Randomly assigns the incidents to users on call (requires shift management) and users on call.
https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/users-and-roles/shift-management.html#idf554fd0f-f93b-40cd-9111-1393bf25ac6e

Incident Ids should be passed in as a comma separated list.

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

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incident_id | The Incident IDs to reassign, can be a comma separated list \(e.g. 1,2,3,4\) |

## Outputs
---
There are no outputs for this script.
