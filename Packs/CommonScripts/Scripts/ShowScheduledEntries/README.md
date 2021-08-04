Shows all scheduled entries for the specific incident.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incidentId | The incident ID to get the tasks from. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ScheduledEntries | The entire scheduled entry object. | Unknown |
| ScheduledEntries.id | The entry ID. | string |
| ScheduledEntries.contents | The entry contents (the scheduled command). | string |
| ScheduledEntries.type | The entry type. | number |
| ScheduledEntries.investigationID | The entry's investigation ID. | string |
| ScheduledEntries.schedule.startDate | The entry's scheduled start date. | Unknown |
| ScheduledEntries.schedule.EndingType | The entry's scheduled ending type. Can be, "by" or "after". | Unknown |
| ScheduledEntries.schedule.Times | The entry's scheduled time until end. This applies when the ending type is "by". | number |
| ScheduledEntries.schedule.EndingDate | The entry's scheduled end time. This applies when the ending type is "after". | Unknown |
| ScheduledEntries.schedule.cron | The entry schedule CRON. | string |
| ScheduledEntries.schedule.HumanCron | The entry schedule settings. | Unknown |
