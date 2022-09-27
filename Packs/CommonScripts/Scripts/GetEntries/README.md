Collect entries matching to the conditions in the war room

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
| tags | The list of tags |
| categories | The list of categories. {commandAndResults, playbookTaskResult, playbookTaskStartAndDone, playbookErrors, justFound, deleted, incidentInfo, chats, evidence, notes, attachments} |

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
