Resolves comma-separated publisher names to the `{publisher_id, publisher_name}` JSON array that ***netskopev2-create-private-app***/***netskopev2-update-private-app*** expect for their `publishers` argument. ***netskopev2-list-publishers*** has no name filter argument, so this fetches all publishers and resolves each requested name to its publisher_id in Python.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Dependencies

---
This script uses the following commands and scripts.

* netskopev2-list-publishers

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| publisher_names | Comma-separated publisher names to resolve to publisher_id (matched case-insensitively against netskopev2-list-publishers' publisher_name field). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ResolvedPublishers.publishers_json | JSON array of \{publisher_id, publisher_name\} objects, ready to pass as the "publishers" argument. Empty if any name failed to resolve. | String |
| ResolvedPublishers.error | Error message if any name didn't resolve (not found, or ambiguous multiple matches). Empty on success. | String |
