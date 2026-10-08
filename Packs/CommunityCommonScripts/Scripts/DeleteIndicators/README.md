Delete indicators based on query, values, or IDs.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_query | Query for indicators to delete. The query is used as-is, so make sure it is scoped to only the indicators you intend to delete. |
| indicator_values | Comma-separated list of indicator values to delete. Values are matched literally, so a value containing a comma must be supplied as a list rather than as a single comma-separated string. |
| indicator_ids | Comma-separated list of indicator IDs to delete. |
| exclude | Whether to add the deleted indicator to the Exclusion List. |
| exclusion_reason | Reason for indicator exclusion. |

## Notes

---

Deletion is permanent and cannot be undone. By default the deleted indicators are not added to the Exclusion List, so they can be re-ingested by a feed afterwards.

Indicator values and IDs are always matched as literal text. Characters that are meaningful in a query, such as `*`, `?`, `:` and `"`, are escaped and therefore cannot change which indicators are matched.

As a safeguard, the script refuses to run when the resolved query would match every indicator, for example `*` or `value:(*)`. To delete in bulk deliberately, pass an explicit `indicator_query`.

## Outputs

---
There are no outputs for this script.
