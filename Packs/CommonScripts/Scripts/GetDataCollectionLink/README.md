Generates the URL for a Data Collection Task into Context.  Can be used to get the url for tasks send via Email, Slack, or even if you select "By Task Only".

To generate links for specific users, add an array of users in the users argument.

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
| task_id | The data collection task ID. |
| users | The array of users the data collection task was sent to, or that you want to send to \(If using by task only\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DataCollectionURL.url | The data collection URL | String |
| DataCollectionURL.task | The task ID for the generated URL | Unknown |
| DataCollectionURL.user | The user for which the data collection link was generated | Unknown |
