Pre-processing script behind the shipped rule **GIB Rule All Types**. The pack does not install the rule on Cortex XSIAM and the Cortex platform. For an incoming incident with a GIB ID it finds the open incidents of the same incident type with the same GIB ID (`gibid:"<id>" and type:"<type>" and -status:closed`, paged, at most 1000). For an open proxy they must also share the *GIB Proxy Port* (each port is a listing of its own), and for a data breach the *GIB Leak Name* and *GIB Upload Time* (one credential comes back with every leak and upload it appears in). It copies the incoming custom fields, name, occurred time and details onto each of them with `setIncident`; when `setIncident` rejects the full update, for example over a grid field value, it retries the scalar fields alone. It drops the incoming incident once at least one duplicate was updated, or when there was nothing to copy. Severity, owner, status, type and playbook of the existing incidents are never touched; closed incidents are not reopened (a re-sent record whose incident is closed creates a new incident); if every update fails the incoming incident is kept. An incident whose type an analyst changed by hand no longer matches, so the record opens a new incident. A phishing group that Group-IB flags as a false positive or allow-listed is never kept: its *GIB False Positive* or *GIB Allow Listed* reaches the open incident of the group with the copied fields, and the record is dropped even when no incident matches or the update fails. The integration hands such a record to the rule only while its setting *Pass flagged phishing groups to the pre-processing rule* is enabled. If the rule shows no script after installation, test an instance of the Group-IB Threat Intelligence integration (**Test** in its settings), which sets it, or select the script in the rule.

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
