This automation calculates the similarity ratio between text and a list of strings and outputs a decimal value between 0.0 and 1.0 (1.0 if the sequences are identical, and 0.0 if they don't have anything in common).

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.9.0 |

## Used In

---
This script is used in the following playbooks and scripts.

RDP Bitmap Cache - Detect and Hunt

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| string_A | First input string. |
| string_B | Second input string. |
| similarity_threshold | The similarity threshold to show results for, a value between 0 &lt; x &gt;1. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| StringSimilarity.SimilarityScore | Similarity score - a value between 1.0 if the sequences are identical, and 0.0 if they have nothing in common. | Unknown |
