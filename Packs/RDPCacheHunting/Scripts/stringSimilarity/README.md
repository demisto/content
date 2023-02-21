This automation calculates the similarity ratio between a Text and a list of strings and outputs a decimal value between 0.0 and 1.0 (1.0 if the sequences are identical, and 0.0 if they don't have anything in common).

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* RDP Bitmap Cache - Detect and Hunt

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| text | The text to match for strings |
| list_of_strings | A list of strings to match in the text |
| similiarity_threshold | The similiarity threshold to show results for, a value between 0 &amp;lt; x &amp;gt;1 |

## Outputs

---
There are no outputs for this script.
