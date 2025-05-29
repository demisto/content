Asimily Preprocessing Rule for Deduplication of incoming incident. The script will be used for creating Pre-Process Rules for Incidents to avoid creating duplicate incidents. Comparison is based on incident `type` and `dbotMirrorId`.

## Permissions

---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations> for Cortex XSOAR 8 Cloud, see the <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script> for Cortex XSOAR 8 On-prem, see the <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script>.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | preProcessing |

## Inputs

---
There are no inputs for this script.

## Outputs

---
Returns `False` if incident already exists to Drop incoming incident. Otherwise return `True`.
