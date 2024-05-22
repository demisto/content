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
| CreateYARARuleIndocators.value | The YARA Rule name | string |
| CreateYARARuleIndocators.description | The YARA Rule description. | string |
| CreateYARARuleIndocators.rawrule | The raw YARA Rule in code block format. | string |
| CreateYARARuleIndocators.rulecondition | The YARA Rule condition. | string |
| CreateYARARuleIndocators.strings | The YARA Rule strings in grid format. | string |
| CreateYARARuleIndocators.tags | The YARA Rule tags. | string |
