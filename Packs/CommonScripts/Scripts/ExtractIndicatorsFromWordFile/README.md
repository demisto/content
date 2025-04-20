Used to extract indicators from Word files (DOC, DOCX).
The script does not extract data from macros (e.g., embedded code).

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | parser, autoextract, doc, docx, word |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Extract Indicators From File - Generic
* Extract Indicators From File - Generic v2

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | The entry ID of the word document to be parsed for indicators. The document can be either in DOC or DOCX format. |

## Outputs
---
There are no outputs for this script.
