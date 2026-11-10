Fetches all publishers and resolves each requested name to its `publisher_id`, building the `{publisher_id, publisher_name}` JSON array that ***netskopev2-create-private-app*** and ***netskopev2-update-private-app*** expect for their `publishers` argument. This is necessary because ***netskopev2-list-publishers*** has no name filter argument.

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
| publisher_names | The comma-separated publisher names to resolve to publisher_id (matched case-insensitively against netskopev2-list-publishers' publisher_name field). Not marked required at the platform level - an empty value is handled inside the script (sets Netskope.ResolvedPublishers.Error) rather than blocking the task from running at all. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Netskope.ResolvedPublishers.PublishersJson | The JSON array of {publisher_id, publisher_name} objects, ready to pass as the "publishers" argument. Empty if any name failed to resolve. | String |
| Netskope.ResolvedPublishers.Error | The error message if any name didn't resolve (not found, or ambiguous multiple matches). Empty on success. | String |
