## Cortex - Fill Support Ticket

Fills a Cortex support ticket by classifying the issue, parsing the taxonomy, and collecting required fields.

### Flow

1. Verifies the user has the required permissions to manage support tickets.
2. Sets playbook inputs to context and retrieves the support ticket taxonomy.
3. Classifies the ticket using AI based on the description and taxonomy.
4. Parses the classification result into issue category and problem concentration.
5. Fills the support ticket with all collected fields.

### Inputs

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| description | A detailed description of the issue. Include error messages/codes or other identifying details. Limited to 25-32000 chars. | Required |
| contact_number | The preferred contact number for follow-up. | Optional |
| issue_impact | The impact of the issue on the system or business. | Optional |
| issue_frequency | The frequency of the issue. | Optional |
| most_recent_issue_start_time | The start date and time of the most recent occurrence of the issue. | Optional |

### Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.SupportTicket.description | The description of the support ticket. | String |
| Core.SupportTicket.contactNumber | The contact number associated with the ticket. | String |
| Core.SupportTicket.IssueImpact | The impact level of the ticket. | String |
| Core.SupportTicket.OngoingIssue | The frequency status of the issue. | String |
| Core.SupportTicket.DateTimeOfIssue | The timestamp of the issue occurrence. | Number |
| Core.SupportTicket.smeArea | The issue category assigned to the ticket. | String |
| Core.SupportTicket.subGroupName | The problem concentration assigned to the ticket. | String |
