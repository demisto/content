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
| entryID | An entry ID for a file containing YARA signatures. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CreateYARARuleIndicators.value | The YARA Rule name | string |
| CreateYARARuleIndicators.description | The YARA Rule description. | string |
| CreateYARARuleIndicators.rawrule | The raw YARA Rule in code block format. | string |
| CreateYARARuleIndicators.rulecondition | The YARA Rule condition. | string |
| CreateYARARuleIndicators.strings | The YARA Rule strings in grid format. | string |
| CreateYARARuleIndicators.tags | The YARA Rule tags. | string |
