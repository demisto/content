Collect entries matching to the conditions in the war room.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| id | Optional incident ID to fetch entries from. If not specified, current incident is used. |
| tags | The list of tags. |
| categories | The list of categories. \(commandAndResults, playbookTaskResult, playbookTaskStartAndDone, playbookErrors, justFound, deleted, incidentInfo, chats, evidence, notes, attachments\). |
| page_size | The number of entries to return. Maximum is 1000. |
| last_id | Return entries starting from the specified entry ID and backward. |
| first_id | Return entries starting from the specified entry ID and forward. |
| selected_entry_id | Return entries before and after the specified entry ID. |
| users | Return entries with the specified users. |
| tags_and_operator | Whether to return entries that include all specified tags. |
| from_time | Return entries from this time and forward. Format is ISO8601 \(i.e., '2020-04-30T10:35:00.000Z'\). |
| parent_id | The ID of the parent entry. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Entry.ID | Entry ID. | Unknown |
| Entry.Type | Entry Type. | Unknown |
| Entry.Tags | Tags associated with the entry. | Unknown |
| Entry.Category | Entry categories. | Unknown |
| Entry.Created | Creation time of the entry. | Unknown |
| Entry.Modified | Last modified time of the entry. | Unknown |
