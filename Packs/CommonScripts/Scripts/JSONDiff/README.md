# Script to Compare JSON Files and Output Differences

This script compares two JSON files and returns their differences, such as added, removed, or changed fields, in a structured format.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| old_json | The first JSON object to compare. |
| new_json | The second JSON object to compare. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| JSONDiff.changed | List of fields that have changed between the two JSONs. | Array |
| JSONDiff.added | List of fields that were added in the second JSON. | Array |
| JSONDiff.removed | List of fields that were removed from the first JSON. | Array |

## Example

---

### Input

```json
{
  "old_json": "{\"a\": 1, \"b\": 2}",
  "new_json": "{\"a\": 1, \"b\": 3}"
}
