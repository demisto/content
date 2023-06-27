Used to extract indicators from Word files (DOC, DOCX).
The script does not extract data from macros (e.g., embedded code).

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations)

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
