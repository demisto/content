Collect entries matching to the conditions in the war room

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
| id | Optional incident ID to fetch entries from. If not specified, current incident is used. |
| pageSize | The number of entries to return. |
| lastId | Return entries starting from the specified entry ID and backward. |
| firstID | Return entries starting from the specified entry ID and forward. |
| selectedEntryID | Return entries before and after the specified entry ID. |
| categories | The list of categories |
| tags | The list of tags |
| users | The list of specified users |
| tagsAndOperator | Return entries that include all specified tags. |
| fromTime | Return entries from this time and forward. |
| parentID | The ID of the parent entry. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Entry.ID | Entry ID | Unknown |
| Entry.Type | Entry Type | Unknown |
| Entry.Tags | Tags associated with the entry | Unknown |
| Entry.Category | Entry categories | Unknown |
| Entry.Created | Creation time of the entry | Unknown |
| Entry.Modified | Last modified time of the entry | Unknown |
