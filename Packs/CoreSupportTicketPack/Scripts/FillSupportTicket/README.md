## FillSupportTicket

Returns fields for the completion of the support ticket.

### Inputs

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| description | A detailed description of the issue. Include error messages/codes or other identifying details. Limited to 25-32000 chars. | Optional |
| contact_number | The preferred contact number for follow-up. | Optional |
| issue_frequency | The frequency of the issue. Options: Yes - Consistent, Yes - Intermittent, Not Applicable. | Optional |
| most_recent_issue_start_time | The start date and time of the most recent occurrence of the issue. | Optional |
| issue_impact | The impact of the issue on the system or business. Options: P0, P1, P2, P3, P4. | Optional |
| issue_category | The category of the issue. | Optional |
| problem_concentration | The specific problem concentration. | Optional |

### Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.SupportTicket.description | The description of the filed support ticket. | String |
| Core.SupportTicket.contactNumber | The contact number associated with the ticket. | String |
| Core.SupportTicket.OngoingIssue | The frequency status of the issue. | String |
| Core.SupportTicket.DateTimeOfIssue | The timestamp of the issue occurrence. | Number |
| Core.SupportTicket.IssueImpact | The impact level of the ticket. | String |
| Core.SupportTicket.smeArea | The category of the issue. | String |
| Core.SupportTicket.subGroupName | The specific problem concentration. | String |
