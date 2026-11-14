Pre-processing script of the rule **GIB Rule**, which ships disabled. The pack does not install the rule on Cortex XSIAM and the Cortex platform. The script works like GIBTIIncidentUpdateAllTypes with two differences: it reads one page of at most 200 open incidents, and it takes the GIB ID from the custom fields or the top level only. It copies the custom fields, name, occurred time and details onto the open incidents of the same incident type with the same GIB ID (for an open proxy, also the same *GIB Proxy Port*; for a data breach, also the same *GIB Leak Name* and *GIB Upload Time*) and drops the incoming incident once one of them was updated (or when there was nothing to copy); the severity, owner, status, type and playbook of the existing incidents stay as they are, and closed incidents are left alone. A phishing group that Group-IB flags as a false positive or allow-listed is never kept. The rule itself skips GIB Data Breach incidents; the data-breach matching applies when the script runs from a rule of your own.

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
