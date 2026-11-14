Variant of GIBTIIncidentUpdate for rules you create yourself. It updates the incidents of the same incident type sharing the incoming GIB ID, the 200 most recent, closed ones included; for an open proxy they must also share the *GIB Proxy Port*, and for a data breach the *GIB Leak Name* and *GIB Upload Time*. It drops the incoming incident once one of them was updated (or when there was nothing to copy); with no match, or when every update failed, the incoming incident is kept. The severity, owner, status, type and playbook of the incidents it updates stay as they are. Use it when a re-sent record must land on the original incident even after it was closed. A phishing group that Group-IB flags as a false positive or allow-listed is never kept: the flag reaches the matching incident, and the record is dropped.

## Permissions

---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations> for Cortex XSOAR 8 Cloud, see the <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script> for Cortex XSOAR 8 On-prem, see the <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script>.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | preProcessing |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---
There are no inputs for this script.

## Outputs

---
There are no outputs for this script.
