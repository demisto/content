Gets a list of indicator objects and the associated indicator outputs that match the specified query and filters. The results are returned in a structured data file.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | The indicators query. |
| dontPopulateFields | A comma-separated list of fields in the object to ignore. |
| limit | The maximum number of indicators to fetch. |
| offset | The results offset page. Only change when the number of the results exceed the limit. |
| addRandomSalt | Salt for the hash function. |
| fieldsToHash | A comma-separated list of fields to hash. Supports wildcard "\*". |
| populateFields | A comma-separated list of fields in the object to poplulate. Defaults are id, score, and investigationIDs. |

## Outputs
---
There are no outputs for this script.
