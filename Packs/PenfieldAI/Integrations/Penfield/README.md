PenfieldGetAssignee will call PenfieldCore's API with an incident and a list of analysts, and return the analyst Penfield believes the incident should be assigned to. We recommend using the PenfieldAssign Automation, which in turn calls this Command.

## penfield-api-call Command
---

| **Argument Name** | **Description** |
| --- | --- |
| analyst_ids | A list of the ids of the analysts to be considered. |
| category | The category of the incident to assign. |
| created | The creation_date of the incident to assign. |
| id | The id of the incident to assign. |
| name | The name of the incident to assign. |
| severity | The severity of the incident to assign. |

## Outputs
---
There are no outputs for this script.

## Examples
---
!penfield-api-call analyst_ids=['analystid1', 'analystid2'] category='my cat' created='2021-09-13T01:58:22.621033322Z' id=34 name='big rootkit attack' severity='High' 