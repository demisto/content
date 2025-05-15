Converts HTML to Markdown.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

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
