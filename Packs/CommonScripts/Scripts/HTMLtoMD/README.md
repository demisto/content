Converts HTML to Markdown.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Test_HTMLtoMD

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| html | HTML to convert to Markdown. |
| escape_misc | When set to False, will skip escaping of miscellaneous punctuation characters such as &amp;, \+, -. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HTMLtoMD.Original | The original HTML that was converted to Markdown. | String |
| HTMLtoMD.Result | The Markdown that was converted from the passed HTML. | String |
