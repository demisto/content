The script will be used for extracting asset information from context data from incidents. If playbook is applied to call `asimily-get-asset-details` for incidents to retrieve asset details, fetched information will be saved in incident's context data under `Asimily`->`Asset`.

## Permissions

---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here:
For Cortex XSOAR 6, see the <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations>.
For Cortex XSOAR 8 Cloud, see the <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script>.
For Cortex XSOAR 8 On-prem, see the <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script>.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | dynamic-section |

## Inputs

---
There are no inputs for this script.

## Outputs

---
Returns formatted markdown table as CommandResults listing attributes fetched from context data under `Asimily`->`Asset`. of incident.
