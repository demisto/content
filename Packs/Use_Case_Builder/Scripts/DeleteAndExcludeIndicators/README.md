This is a custom automation created for the Quick Start Investigation pack

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| indicatorValues | Comma-separated list of indicator values to delete. Values are matched literally, so a value containing a comma must be supplied as a list rather than as a single comma-separated string. |
| reason | Reason for the deletion. |

## Notes

---

Deletion is permanent and cannot be undone. The deleted indicators are added to the Exclusion List.

Indicator values are always matched as literal text. Characters that are meaningful in a query, such as `*`, `?`, `:` and `"`, are escaped and therefore cannot change which indicators are matched.

As a safeguard, the script refuses to run when the resolved query would match every indicator, and reports an error when no indicator values are supplied.
