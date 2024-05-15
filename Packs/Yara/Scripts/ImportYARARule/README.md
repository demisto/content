## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| string | One or more YARA signatures in string format. |
| entryID | An entry ID with for a file containing YARA signatures. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ImportYARARule.value | The YARA Rule name | string |
| ImportYARARule.description | The YARA Rule description. | string |
| ImportYARARule.rawrule | The raw YARA Rule in code block format. | string |
| ImportYARARule.rulecondition | The YARA Rule condition. | string |
| ImportYARARule.strings | The YARA Rule strings in grid format. | string |
| ImportYARARule.tags | The YARA Rule tags. | string |
