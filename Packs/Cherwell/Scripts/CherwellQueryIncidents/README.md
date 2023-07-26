This script is an example script of how to query incidents from Cherwell. The script wraps the cherwell-query-business-object command of the cherwell integration. When writing your own script to query  business objects, follow the instructions found in the configuration section of the script, but do not change the execution section.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Cherwell |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* cherwell-query-business-object

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| query | The query to run. The query is a list of comma-seperated filters such that each filter should be of the form: \["field_name","operator","value"\] and operator is one of: 'eq'=equal, 'gt'=greater-than, 'lt'=less-than, 'contains', 'startwith'. Special characters shoud be escaped.<br/>Example: \`\[\["CreatedDateTime":"gt":"4/10/2019 3:10:12 PM"\]\["Priority","eq","1"\]\]\`. <br/>NOTICE: If multiple  filters are received for the same field name, an 'OR' operation between the filters is performed. If the field names are different, an 'AND' operation is performed. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Cherwell.QueryResults.RecordId | Recoed ID | String |
| Cherwell.QueryResults.PublicId | Public ID | String |
| Cherwell.QueryResults.Description | Incident description | String |
| Cherwell.QueryResults.Priority | Incident ptiority | Number |
| Cherwell.QueryResults.OwnedBy | Incident owned by field | String |
| Cherwell.QueryResults.Service | Service needed for the incident | String |
| Cherwell.QueryResults.CustomerDisplayName | Incident reporting customer  | String |
| Cherwell.BusinessObject.CreatedDateTime | Created date time | String |
| Cherwell.BusinessObject.TotalTasks | Total tasks for this incident | Number |
