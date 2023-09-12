Show clustering model information - model summary and incidents in specific cluster.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | widget |
| Cortex XSOAR Version | 6.2.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| modelName | The model name. |
| searchQuery | The input query from the dashboard. |
| fromDate | The start date by which to filter incidents. Date format will be the same as in the incidents query page, for example: "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| fieldsToDisplay | Comma-separated list of additional incident fields to display, but which will not be taken into account when computing similarity. |
| returnType | Return model summary or incidents in specific group according to the search query. |

## Outputs

---
There are no outputs for this script.
