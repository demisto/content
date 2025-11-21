Checks the given datetime has occurred before the provided relative time.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | date, filter, Condition |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| left | Date value to check - Can be any time format. ex. "2020-01-01T00:00:00" |
| right | Relative time ex. "6 months ago" |

## Outputs

---
The script returns a boolean value (`true` or `false`) indicating if the date is before the relative time.
