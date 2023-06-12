IT service management
## Configure ServiceNow v2_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ServiceNow v2_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | ServiceNow URL, in the format https://company.service-now.com/ | True |
    | Username | False |
    | Password | False |
    | Default ticket type for running ticket commands and fetching incidents | False |
    | ServiceNow API Version (e.g. 'v1') | False |
    | Fetch incidents | False |
    | The query to use when fetching incidents | False |
    | How many incidents to fetch each time | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False |
    | Timestamp field to filter by (e.g., `opened_at`) This is how the filter is applied to the query: "ORDERBYopened_at^opened_at&gt;[Last Run]".<br/>To prevent duplicate incidents, this field is mandatory for fetching incidents. | False |
    | ServiceNow ticket column to be set as the incident name, default is the incident number | False |
    | Incident type | False |
    | Get incident attachments | False |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### servicenow-get-ticket

***
Retrieves ticket information by ticket ID.

#### Base Command

`servicenow-get-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket system ID for which to retrieve information. | Optional | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". Possible values are: incident, problem, change_request, sc_request, sc_task, sc_req_item. Default is incident. | Optional | 
| number | Ticket number to retrieve. | Optional | 
| get_attachments | If "true" will retrieve ticket attachments. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| custom_fields | Custom fields on which to query. For example: state_code=AR,time_zone=PST. | Optional | 
| additional_fields | Additional fields to display in the War Room entry and incident context. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | string | ServiceNow ticket ID. | 
| ServiceNow.Ticket.OpenedBy | string | ServiceNow ticket opener ID. | 
| ServiceNow.Ticket.CreatedOn | date | ServiceNow ticket creation date. | 
| ServiceNow.Ticket.Assignee | string | ServiceNow ticket assignee ID. | 
| ServiceNow.Ticket.State | string | ServiceNow ticket state. | 
| ServiceNow.Ticket.Summary | string | ServiceNow ticket short summary. | 
| ServiceNow.Ticket.Number | string | ServiceNow ticket number. | 
| ServiceNow.Ticket.Active | boolean | ServiceNow ticket active. | 
| ServiceNow.Ticket.AdditionalComments | string | ServiceNow ticket comments. | 
| ServiceNow.Ticket.Priority | string | ServiceNow ticket priority. | 
| ServiceNow.Ticket.OpenedAt | date | ServiceNow ticket opening time. | 
| ServiceNow.Ticket.ResolvedBy | string | ServiceNow ticket resolver ID. | 
| ServiceNow.Ticket.CloseCode | string | ServiceNow ticket close code. | 
| File.Info | string | Attachment file info. | 
| File.Name | string | Attachment file name. | 
| File.Size | number | Attachment file size. | 
| File.SHA1 | string | Attachment file SHA1 hash. | 
| File.SHA256 | string | Attachment file SHA256 hash. | 
| File.EntryID | string | Attachment file entry ID. | 
| File.Type | string | Attachment file type. | 
| File.MD5 | string | Attachment file MD5 hash. | 

### servicenow-create-ticket

***
Creates new ServiceNow ticket.

#### Base Command

`servicenow-create-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| short_description | Short description of the ticket. | Optional | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". Possible values are: incident, problem, change_request, sc_request, sc_task, sc_req_item. Default is incident. | Optional | 
| urgency | Ticket urgency. You can either select from the predefined options or enter another value, for example: "Urgent" or "5". Possible values are: 3 - Low, 2 - Medium, 1 - High. | Optional | 
| severity | Ticket severity. You can either select from the predefined options or enter another value, for example: "Urgent" or "5". Possible values are: 3 - Low, 2 - Medium, 1 - High. | Optional | 
| impact | Ticket impact. Possible values are: 3 - Low, 2 - Medium, 1 - High. | Optional | 
| active | Whether to set the ticket as Active. Can be "true" or "false". Possible values are: true, false. | Optional | 
| activity_due | The ticket activity due date, in the format "2016-07-02 21:51:11". | Optional | 
| additional_assignee_list | List of users assigned to the ticket. | Optional | 
| approval_history | Ticket history approval. | Optional | 
| approval_set | The ticket approval set date, in the format "2016-07-02 21:51:11". | Optional | 
| assigned_to | User assigned to the ticket. | Optional | 
| business_duration | Business duration, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| business_service | Business service. | Optional | 
| business_stc | Business source. | Optional | 
| calendar_duration | Calendar duration, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| caller_id | Caller ID (UID format). | Optional | 
| category | Category of the ticket. | Optional | 
| caused_by | UID Format. | Optional | 
| close_code | Ticket's close code. Can be "Solved (Work Around)", "Solved (Permanently)", "Solved Remotely (Work Around)", "Solved Remotely (Permanently)", "Not Solved (Not Reproducible)", "Not Solved (Too Costly)", or "Closed/Resolved by Caller". Possible values are: Solved (Work Around), Solved (Permanently), Solved Remotely (Work Around), Solved Remotely (Permanently), Not Solved (Not Reproducible), Not Solved (Too Costly), Closed/Resolved by Caller. | Optional | 
| close_notes | Close notes of the ticket. | Optional | 
| closed_at | When the ticket was closed, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| closed_by | User who closed the ticket. | Optional | 
| cmdb_ci | UID Format. | Optional | 
| comments | Format type journal input. | Optional | 
| comments_and_work_notes | Format type journal input. | Optional | 
| company | Company (UID format). | Optional | 
| contact_type | Contact type. | Optional | 
| correlation_display | Correlation display. | Optional | 
| correlation_id | Correlation ID. | Optional | 
| delivery_plan | Delivery plan (UID format). | Optional | 
| display | Whether to display comments, work notes, and so on. Can be "true" or "false". Possible values are: true, false. | Optional | 
| description | Ticket description. | Optional | 
| due_date | Ticket due date, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| escalation | Escalation. | Optional | 
| expected_start | Expected start date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| follow_up | Follow up date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| group_list | UID format list (group). | Optional | 
| knowledge | Whether the ticket is solved in the knowledge base. Can be "true" or "false". Possible values are: true, false. | Optional | 
| location | Location of the ticket. | Optional | 
| made_sla | SLA of the ticket. | Optional | 
| notify | Whether to be notified about this ticket. Can be "1" or "0". Possible values are: 1, 0. | Optional | 
| order | Order number. | Optional | 
| parent | UID Format. | Optional | 
| parent_incident | UID Format. | Optional | 
| problem_id | UID Format. | Optional | 
| reassignment_count | The number of users included in this ticket. | Optional | 
| reopen_count | How many times the ticket has been reopened. | Optional | 
| resolved_at | The date/time that the ticket was resolved, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| resolved_by | ID of the user that resolved the ticket. | Optional | 
| rfc | UID. | Optional | 
| sla_due | SLA due date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| subcategory | Ticket subcategory. | Optional | 
| sys_updated_by | Last updated by. | Optional | 
| sys_updated_on | Last date/time that the system was updated, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| user_input | Input from the end user. | Optional | 
| watch_list | A list of watched tickets. | Optional | 
| work_end | Format: YYYY-MM-DD HH:MM:SS. | Optional | 
| work_notes | Format journal list. | Optional | 
| work_notes_list | List work notes UIDs. | Optional | 
| work_start | Date/time when work started on the ticket. | Optional | 
| assignment_group | The sys_id of the group to assign. | Optional | 
| incident_state | The number that represents the incident state. | Optional | 
| number | Ticket number. | Optional | 
| priority | Priority of the ticket. Possible values are: 5 - Planning, 4 - Low, 3 - Moderate, 2 - High, 1 - Critical. | Optional | 
| template | Template name to use as a base to create new tickets. | Optional | 
| custom_fields | Custom (user defined) fields in the format: fieldname1=value;fieldname2=value; custom fields start with a "u_". | Optional | 
| change_type | Type of Change Request ticket. Can be "normal", "standard", or "emergency". Default is "normal". Possible values are: normal, standard, emergency. Default is normal. | Optional | 
| state | State of the ticket, for example: "Closed" or "7" or "7 - Closed". | Optional | 
| opened_at |  Date/time the ticket was opened, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| caller | Caller system ID. | Optional | 
| approval | Ticket approval. | Optional | 
| additional_fields | Additional fields in the format: fieldname1=value;fieldname2=value;. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | string | ServiceNow ticket ID. | 
| ServiceNow.Ticket.OpenedBy | string | ServiceNow ticket opener ID. | 
| ServiceNow.Ticket.CreatedOn | date | ServiceNow ticket creation date. | 
| ServiceNow.Ticket.Assignee | string | ServiceNow ticket assignee ID. | 
| ServiceNow.Ticket.State | string | ServiceNow ticket state. | 
| ServiceNow.Ticket.Summary | string | ServiceNow ticket short summary. | 
| ServiceNow.Ticket.Number | string | ServiceNow ticket number. | 
| ServiceNow.Ticket.Active | boolean | ServiceNow ticket active. | 
| ServiceNow.Ticket.AdditionalComments | string | ServiceNow ticket comments. | 
| ServiceNow.Ticket.Priority | string | ServiceNow ticket priority. | 
| ServiceNow.Ticket.OpenedAt | date | ServiceNow ticket opening time. | 
| ServiceNow.Ticket.ResolvedBy | string | ServiceNow ticket resolver ID. | 
| ServiceNow.Ticket.CloseCode | string | ServiceNow ticket close code. | 

### servicenow-update-ticket

***
Updates the specified ticket.

#### Base Command

`servicenow-update-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| short_description | Short description of the ticket. | Optional | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". Possible values are: incident, problem, change_request, sc_request, sc_task, sc_req_item. Default is incident. | Optional | 
| urgency | Ticket urgency. You can either select from the predefined options or enter another value, for example: "Urgent" or "5". Possible values are: 3 - Low, 2 - Medium, 1 - High. | Optional | 
| severity | Ticket severity. You can either select from the predefined options or enter another value, for example: "Urgent" or "5". Possible values are: 3 - Low, 2 - Medium, 1 - High. | Optional | 
| impact | Ticket impact. Possible values are: 3 - Low, 2 - Medium, 1 - High. | Optional | 
| active | Whether the ticket is Active. Can be "true" or "false". Possible values are: true, false. | Optional | 
| activity_due | The ticket activity due date, in the format: "2016-07-02 21:51:11". | Optional | 
| additional_assignee_list | List of users assigned to the ticket. | Optional | 
| approval_history | Ticket history approval. | Optional | 
| approval_set | The ticket approval set date/time, in the format: "2016-07-02 21:51:11". | Optional | 
| assigned_to | User assigned to the ticket. | Optional | 
| business_duration | Business duration, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| business_service | Business service. | Optional | 
| business_stc | Business source. | Optional | 
| calendar_duration | Calendar duration, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| caller_id | Caller ID (UID format). | Optional | 
| category | Category name. | Optional | 
| caused_by | UID format. | Optional | 
| close_code | Ticket's close code. Ticket's close code. Can be "Solved (Work Around)", "Solved (Permanently)", "Solved Remotely (Work Around)", "Solved Remotely (Permanently)", "Not Solved (Not Reproducible)", "Not Solved (Too Costly)", or "Closed/Resolved by Caller". Possible values are: Solved (Work Around), Solved (Permanently), Solved Remotely (Work Around), Solved Remotely (Permanently), Not Solved (Not Reproducible), Not Solved (Too Costly), Closed/Resolved by Caller. | Optional | 
| close_notes | Close notes of the ticket. | Optional | 
| closed_at | Date/time the ticket was closed, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| closed_by | User who closed the ticket. | Optional | 
| cmdb_ci | UID Format. | Optional | 
| comments | Format type journal input. | Optional | 
| comments_and_work_notes | Format type journal input. | Optional | 
| company | UID Format. | Optional | 
| contact_type | Contact type. | Optional | 
| correlation_display | Correlation display. | Optional | 
| correlation_id | Correlation ID. | Optional | 
| delivery_plan | UID Format. | Optional | 
| display | Whether to display comments, work notes, and so on. Can be "true" or "false". Possible values are: true, false. | Optional | 
| description | Ticket description. | Optional | 
| due_date | Ticket due date, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| escalation | Escalation. | Optional | 
| expected_start | Expected start date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| follow_up | Follow up date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| group_list | UID format list. | Optional | 
| knowledge | Whether the ticket is solved in the knowledge base. Can be "true" or "false". Possible values are: true, false. | Optional | 
| location | Location of the ticket. | Optional | 
| made_sla | SLA of the ticket. | Optional | 
| notify | Whether to be notified about this ticket. Can be "1" or "0". Possible values are: 1, 0. | Optional | 
| order | Order number. | Optional | 
| parent | Parent (UID format). | Optional | 
| parent_incident | Parent incident (UID format). | Optional | 
| problem_id | Problem ID (UID format). | Optional | 
| reassignment_count | The number of users included in this ticket. | Optional | 
| reopen_count | The number of times the ticket has been reopened. | Optional | 
| resolved_at | Date/time the ticket was resolved, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| resolved_by | Resolved by (UID format). | Optional | 
| rfc | UID. | Optional | 
| sla_due | SLA due date/time, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| subcategory | Ticket subcategory. | Optional | 
| sys_updated_by | Last updated by. | Optional | 
| sys_updated_on | Date/time the system was last updated. | Optional | 
| user_input | Input from the end user. | Optional | 
| watch_list | A list of watched tickets. | Optional | 
| work_end | Format: YYYY-MM-DD HH:MM:SS. | Optional | 
| work_notes | Format journal list. | Optional | 
| work_notes_list | Comma-separated list of work notes UIDs. | Optional | 
| work_start | Date/time when work started on the ticket. | Optional | 
| assignment_group | Assignment group UID. | Optional | 
| incident_state | Number representing the incident state. | Optional | 
| number | Ticket number. | Optional | 
| priority | Priority of the ticket. Possible values are: 5 - Planning, 4 - Low, 3 - Moderate, 2 - High, 1 - Critical. | Optional | 
| id | System ID of the ticket to update. | Required | 
| custom_fields | Custom (user defined) fields in the format: fieldname1=value;fieldname2=value; custom fields start with a "u_". | Optional | 
| change_type | Type of Change Request ticket. Can be "normal", "standard", or "emergency". Default is "normal". Possible values are: normal, standard, emergency. Default is normal. | Optional | 
| state | State of the ticket, for example: "Closed" or "7" or "7 - Closed". | Optional | 
| caller | Caller system ID. | Optional | 
| approval | Ticket approval. | Optional | 
| additional_fields | Additional fields in the format: fieldname1=value;fieldname2=value;. | Optional | 

#### Context Output

There is no context output for this command.
### servicenow-delete-ticket

***
Deletes a ticket from ServiceNow.

#### Base Command

`servicenow-delete-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Possible values are: incident, problem, change_request, sc_request, sc_task, sc_req_item. | Optional | 

#### Context Output

There is no context output for this command.
### servicenow-query-tickets

***
Retrieves ticket information according to the supplied query.

#### Base Command

`servicenow-query-tickets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of tickets to retrieve. Default is 10. | Optional | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". Possible values are: incident, problem, change_request, sc_request, sc_task. Default is incident. | Optional | 
| query | The query to run. To learn about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html. | Optional | 
| offset | Starting record index to begin retrieving records from. Default is 0. | Optional | 
| additional_fields | Additional fields to present in the War Room entry and incident context. | Optional | 
| system_params | System parameters in the format: fieldname1=value;fieldname2=value. For example: "sysparm_display_value=al;&amp;sysparm_exclude_reference_link=True". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | string | The unique ticket identifier. | 
| Ticket.Creator | string | A string field that indicates the user who created the ticket. | 
| Ticket.CreatedOn | date | The date/time when the ticket was created. | 
| Ticket.Assignee | string | Specifies the user assigned to complete the ticket. By default, this field uses a reference qualifier to only display users with the itil role. | 
| Ticket.State | string | Status of the ticket. | 
| Ticket.Summary | string | A human-readable title for the record. | 
| Ticket.Number | string | The display value of the ticket. | 
| Ticket.Active | boolean | Specifies whether work is still being done on a task or whether the work for the task is complete. | 
| Ticket.AdditionalComments | Unknown | Comments about the task record. | 
| Ticket.Priority | string | Specifies the ticket priority for the assignee. | 
| Ticket.OpenedAt | date | The date/time when the ticket was first opened. | 
| Ticket.Escalation | string | Indicates how long the ticket has been open. | 

### servicenow-add-link

***
Adds a link to the specified ticket.

#### Base Command

`servicenow-add-link`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". Possible values are: incident, problem, change_request, sc_request, sc_task. Default is incident. | Optional | 
| link | The actual link to publish in ServiceNow ticket, in a valid URL format, for example, http://www.demisto.com. | Required | 
| post-as-comment | Whether to publish the link as comment on the ticket. Can be "true" or "false". If false will publish the link as WorkNote. | Optional | 
| text | The text to represent the link. | Optional | 

#### Context Output

There is no context output for this command.
### servicenow-add-comment

***
Adds a comment to the specified ticket, by ticket ID.

#### Base Command

`servicenow-add-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". Possible values are: incident, problem, change_request, sc_request, sc_task. Default is incident. | Optional | 
| comment | Comment to add. | Required | 
| post-as-comment | Whether to publish the note as comment on the ticket. Can be "true" or "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
### servicenow-upload-file

***
Uploads a file to the specified ticket.

#### Base Command

`servicenow-upload-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". Possible values are: incident, problem, change_request, sc_request, sc_task. Default is incident. | Optional | 
| file_id | War Room entry ID that includes the file. | Required | 
| file_name | Filename of the uploaded file to override the existing file name in the entry. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.File.Filename | string | Name of the file. | 
| ServiceNow.Ticket.File.Link | string | Download link for the file. | 
| ServiceNow.Ticket.File.SystemID | string | System ID of the file. | 

### servicenow-get-record

***
Retrieves record information, by record ID.

#### Base Command

`servicenow-get-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Record System ID. | Required | 
| fields | Comma-separated list of table fields to display and output to the context, for example: name,tag,company. ID field is added by default. | Optional | 
| table_name | The name of the table from which to get the record. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Record.ID | string | The unique record identifier for the record. | 
| ServiceNow.Record.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Record.UpdatedAt | date | A time-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Record.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Record.CreatedOn | date | A time-stamp field that indicates when a record was created. | 

### servicenow-query-table

***
Queries the specified table in ServiceNow.

#### Base Command

`servicenow-query-table`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table to query. | Required | 
| limit | The maximum number of tickets to retrieve. Default is 10. | Optional | 
| query | The query to run. For more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html. | Optional | 
| fields | Comma-separated list of table fields to display and output to the context, for example: name,tag,company. ID field is added by default. | Optional | 
| offset | Starting record index to begin retrieving records from. Default is 0. | Optional | 
| system_params | System parameters in the format: fieldname1=value;fieldname2=value. For example: "sysparm_display_value=al;&amp;sysparm_exclude_reference_link=True". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Results.ID | string | The unique record identifier for the record. | 
| ServiceNow.Results.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Results.UpdatedAt | date | A time-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Results.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Results.CreatedOn | date | A time-stamp field that indicates when a record was created. | 

### servicenow-create-record

***
Creates a new record in the specified ServiceNow table.

#### Base Command

`servicenow-create-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table in which to create a record. | Required | 
| fields | Fields and their values to create the record with, in the format: fieldname1=value;fieldname2=value;... | Optional | 
| custom_fields | Custom (user defined) fields in the format: fieldname1=value;fieldname2=value;... | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Record.ID | string | The unique record identifier for the record. | 
| ServiceNow.Record.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Record.UpdatedAt | date | A time-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Record.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Record.CreatedOn | date | A time-stamp field that indicates when a record was created. | 

### servicenow-update-record

***
Updates a record in the specified ServiceNow table.

#### Base Command

`servicenow-update-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table to update the record in. | Required | 
| id | The system ID of the ticket to update. | Required | 
| fields | Fields and their values to update in the record, in the format: fieldname1=value;fieldname2=value;... | Optional | 
| custom_fields | Custom (user defined) fields and their values to update in the record, in the format: fieldname1=value;fieldname2=value;... | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Record.ID | string | The unique record identifier for the record. | 
| ServiceNow.Record.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Record.UpdatedAt | date | A time-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Record.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Record.CreatedOn | date | A time-stamp field that indicates when a record was created. | 

### servicenow-delete-record

***
Deletes a record in the specified ServiceNow table.

#### Base Command

`servicenow-delete-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The table name. | Required | 
| id | The system ID of the ticket to delete. | Required | 

#### Context Output

There is no context output for this command.
### servicenow-list-table-fields

***
Lists API fields for the specified ServiceNow table.

#### Base Command

`servicenow-list-table-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Field | string | Table API field name. | 

### servicenow-query-computers

***
Queries the cmdb_ci_computer table in ServiceNow.

#### Base Command

`servicenow-query-computers`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer_id | Query by computer sys_id. | Optional | 
| computer_name | Query by computer name. | Optional | 
| query | Query by specified query, for more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html. | Optional | 
| asset_tag | Query by asset tag. | Optional | 
| limit | Maximum number of query results. Default is 10. Default is 10. | Optional | 
| offset | Starting record index to begin retrieving records from. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Computer.ID | string | Computer system ID. | 
| ServiceNow.Computer.AssetTag | string | Computer Asset tag. | 
| ServiceNow.Computer.Name | string | Computer name. | 
| ServiceNow.Computer.DisplayName | string | Computer display name. | 
| ServiceNow.Computer.SupportGroup | string | Computer support group. | 
| ServiceNow.Computer.OperatingSystem | string | Computer operating system. | 
| ServiceNow.Computer.Company | string | Computer company system ID. | 
| ServiceNow.Computer.AssignedTo | string | Computer assigned to user system ID. | 
| ServiceNow.Computer.State | string | Computer state. | 
| ServiceNow.Computer.Cost | string | Computer cost. | 
| ServiceNow.Computer.Comments | string | Computer comments. | 

### servicenow-query-groups

***
Queries the sys_user_group table in ServiceNow.

#### Base Command

`servicenow-query-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Query by group system ID. | Optional | 
| group_name | Query by group name. | Optional | 
| query | Query by specified query, for more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html. | Optional | 
| limit | Maximum number of query results. Default is 10. Default is 10. | Optional | 
| offset | Starting record index to begin retrieving records from. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Group.ID | string | Group system ID. | 
| ServiceNow.Group.Description | string | Group description. | 
| ServiceNow.Group.Name | string | Group name. | 
| ServiceNow.Group.Manager | string | Group manager system ID. | 
| ServiceNow.Group.Updated | date | Date/time the group was last updated. | 

### servicenow-query-users

***
Queries the sys_user table in ServiceNow.

#### Base Command

`servicenow-query-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Query by user system ID. | Optional | 
| user_name | Query by username. | Optional | 
| query | Query by specified query, for more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html. | Optional | 
| limit | Maximum number of query results. Default is 10. Default is 10. | Optional | 
| offset | Starting record index to begin retrieving records from. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.User.ID | string | User system ID. | 
| ServiceNow.User.Name | string | User name \(first and last\). | 
| ServiceNow.User.UserName | string | User username. | 
| ServiceNow.User.Email | string | User email address. | 
| ServiceNow.User.Created | date | Date/time the user was created. | 
| ServiceNow.User.Updated | date | Date/time the user was last updated. | 

### servicenow-get-table-name

***
Gets table names by a label to use in commands.

#### Base Command

`servicenow-get-table-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label | The table label, for example: Asset, Incident, IP address, and so on. | Required | 
| limit | Maximum number of query results. Default is 10. Default is 10. | Optional | 
| offset | Starting record index to begin retrieving records from. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Table.ID | string | Table system ID. | 
| ServiceNow.Table.Name | string | Table name to use in commands, for example: alm_asset. | 
| ServiceNow.Table.SystemName | string | Table system name, for example: Asset. | 

### servicenow-get-ticket-notes

***
Gets notes from the specified ServiceNow ticket. "Read permissions" are required for the sys_journal_field table.

#### Base Command

`servicenow-get-ticket-notes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| limit | Maximum number of ticket notes. Default is 10. Default is 10. | Optional | 
| offset | Offset of the ticket notes. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | string | Ticket ID. | 
| ServiceNow.Ticket.Note.Value | unknown | Ticket note value. | 
| ServiceNow.Ticket.Note.CreatedOn | date | Date/time the ticket note was created. | 
| ServiceNow.Ticket.Note.CreatedBy | string | User that created the ticket note. | 
| ServiceNow.Ticket.Note.Type | string | Ticket note type. | 

### servicenow-add-tag

***
Adds a tag to a ticket. The added tag entry will be visible in the label_entry table and can be retrieved using the "!servicenow-query-table table_name=label_entry fields=title,table,sys_id,id_display,id_type" command.

#### Base Command

`servicenow-add-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID. | Required | 
| tag_id | Tag system ID. Can be retrieved using the "!servicenow-query-table table_name=label fields=name,active,sys_id" command. | Required | 
| title | Tag title. For example: "Incident - INC000001". | Required | 
| ticket_type | Ticket type. Can be "incident", "problem", "change_request", "sc_request", "sc_task", or "sc_req_item". Default is "incident". Possible values are: incident, problem, change_request, sc_request, sc_task, sc_req_item. Default is incident. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | String | The unique ticket identifier. | 
| ServiceNow.Ticket.TagTitle | String | Ticket tag title. | 
| ServiceNow.Ticket.TagID | String | Ticket tag ID. | 

### servicenow-query-items

***
Queries the sc_cat_item table in ServiceNow.

#### Base Command

`servicenow-query-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Query by name. Does not require an exact match. | Optional | 
| offset | Starting record index to begin retrieving records from. Default is 0. | Optional | 
| limit | Maximum number of query results. Default is 10. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.CatalogItem.ID | String | Catalog item system ID. | 
| ServiceNow.CatalogItem.Name | String | Catalog item name. | 
| ServiceNow.CatalogItem.Description | String | Catalog item description. | 
| ServiceNow.CatalogItem.Price | Number | Catalog item price. | 

### servicenow-get-item-details

***
Retrieves item details by system ID.

#### Base Command

`servicenow-get-item-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Catalog item system ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.CatalogItem.ID | String | Catalog item system ID. | 
| ServiceNow.CatalogItem.Name | String | Catalog item name. | 
| ServiceNow.CatalogItem.Description | String | Catalog item description. | 
| ServiceNow.CatalogItem.Price | Number | Catalog item price. | 
| ServiceNow.CatalogItem.Variables.Mandatory | Boolean | Is the variable mandatory as part of the ordering process. | 
| ServiceNow.CatalogItem.Variables.Name | String | A name to identify the question. | 
| ServiceNow.CatalogItem.Variables.Question | String | Question to ask users ordering the catalog item. | 
| ServiceNow.CatalogItem.Variables.Type | String | The variable type. | 

### servicenow-create-item-order

***
Orders the specified catalog item.

#### Base Command

`servicenow-create-item-order`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Catalog item system ID. | Required | 
| quantity | Quantity of the item to order. | Required | 
| variables | If there are mandatory variables defined for the item, they must be passed to the endpoint. Can be retrieved using the servicenow-get-item-details command. For example, var1=value1;var2=value2. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.OrderRequest.ID | String | Generated request system ID. | 
| ServiceNow.OrderRequest.RequestNumber | String | Number of the generated request. | 

### servicenow-document-route-to-queue

***
Documents a route to a queue. Requires an installation of the Advanced Work Assignments plugin. An active queue and service channel to the designated table.

#### Base Command

`servicenow-document-route-to-queue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_id | Queue ID. Can be retrieved using the "!servicenow-query-table table_name=awa_queue fields=name,number,order" command. | Required | 
| document_table | Document table. Default is incident. | Optional | 
| document_id | Document ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.WorkItem.WorkItemID | String | Unique ID of the work item assigned to the queue. | 
| ServiceNow.WorkItem.DocumentTable | String | Name of the table associated with the document | 
| ServiceNow.WorkItem.DocumentID | String | Unique ID of the document to be routed to the queue. | 
| ServiceNow.WorkItem.QueueID | String | Unique ID of the queue on which to route a document. | 
| ServiceNow.WorkItem.DisplayName | String | Name of the document to be routed by this work item, for example: case record. | 

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and ServiceNow v2_copy corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and ServiceNow v2_copy.
