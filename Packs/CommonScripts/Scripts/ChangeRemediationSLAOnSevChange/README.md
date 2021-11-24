Changes the remediation SLA once a change in incident severity occurs.
This is automatic and changes can be configured to your needs.

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/playbooks/automations.html
](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/playbooks/automations.html)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | field-change-triggered, example |
| Cortex XSOAR Version | 4.1.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| old | The old value of the field that was changed. |
| new | The new value of the field that was changed. |

## Outputs
---
There are no outputs for this script.
