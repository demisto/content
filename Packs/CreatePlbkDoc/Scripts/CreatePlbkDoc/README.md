Purpose:      This automation will produce docx file detailing the tasks in the given playbook. It can produce a table or paragraph format of the report.

Author:       Mahmood Azmat

Input1:       Name of the playbook (Mandatory)
Input2:       Format type needed. Table or Paragraph. Paragraph is default.
Input3:       Name of the docx file that will be produced. Give the full name including the ".docx" extension. (Mandatory)

Requirements: This automation requires "Demisto REST API" integration enabled and connected to the XSOAR itself. Automation uses it to read the objects of the playbook.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | General, Utility |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| DocFileName |  |
| PlaybookName |  |
| Output_Format |  |

## Outputs
---
There are no outputs for this script.
