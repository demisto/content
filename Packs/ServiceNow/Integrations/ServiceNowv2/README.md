IT service management
This integration was integrated and tested with version Orlando of ServiceNow
## Configure ServiceNow v2 on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ServiceNow v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | ServiceNow URL, in the format https://company.service\-now.com/ | True |
| credentials | Username | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |
| ticket_type | Default ticket type for running ticket commands and fetching incidents | False |
| api_version | ServiceNow API Version \(e.g. &\#x27;v1&\#x27;\) | False |
| isFetch | Fetch incidents | False |
| sysparm_query | The query to use when fetching incidents | False |
| fetch_limit | How many incidents to fetch each time | False |
| fetch_time | First fetch timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| timestamp_field | Timestamp field to filter by \(e.g., \`opened\_at\`\)
This is how the filter is applied to the query: “ORDERBYopened\_at^opened\_at&gt;\[Last Run\]. To prevent duplicate incidents, this field is mandatory for fetching incidents. | False |
| incidentType | Incident type | False |
| get_attachments | Get incident attachments | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### servicenow-get-ticket
***
Retrieve ticket information by specific ticket ID


##### Base Command

`servicenow-get-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID | Optional | 
| ticket_type | Ticket type | Optional | 
| number | Ticket number to retrieve | Optional | 
| get_attachments | Whether to retrieve ticket attachments, default false | Optional | 
| custom_fields | Custom fields to query on. e.g: state_code=AR,time_zone=PST.&#x27; | Optional | 
| additional_fields | Additional fields to present in the war room entry and incident context. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | string | ServiceNow ticket ID | 
| ServiceNow.Ticket.OpenedBy | string | ServiceNow ticket opener ID | 
| ServiceNow.Ticket.CreatedOn | date | ServiceNow ticket creation date. | 
| ServiceNow.Ticket.Assignee | string | ServiceNow ticket assignee ID | 
| ServiceNow.Ticket.State | string | ServiceNow ticket state | 
| ServiceNow.Ticket.Summary | string | ServiceNow ticket short summary | 
| ServiceNow.Ticket.Number | string | ServiceNow ticket number | 
| ServiceNow.Ticket.Active | boolean | ServiceNow ticket active | 
| ServiceNow.Ticket.AdditionalComments | string | ServiceNow ticket comments | 
| ServiceNow.Ticket.Priority | string | ServiceNow ticket priority | 
| ServiceNow.Ticket.OpenedAt | date | ServiceNow ticket opening time | 
| ServiceNow.Ticket.ResolvedBy | string | ServiceNow ticket resolver ID | 
| ServiceNow.Ticket.CloseCode | string | ServiceNow ticket close code | 
| File.Info | string | Attachment file info | 
| File.Name | string | Attachment file name | 
| File.Size | number | Attachment file size | 
| File.SHA1 | string | Attachment file SHA1 | 
| File.SHA256 | string | Attachment file SHA256 | 
| File.EntryID | string | Attachment file entry ID | 
| File.Type | string | Attachment file type | 
| File.MD5 | string | Attachment file MD5 | 


##### Command Example
```!servicenow-get-ticket number=INC0000039```

##### Context Example
```
{
    "ServiceNow": {
        "Ticket": {
            "Active": "true",
            "CreatedOn": "2020-01-26 00:42:29",
            "Creator": "id",
            "ID": "id",
            "Number": "INC0000039",
            "OpenedAt": "2020-01-26 00:41:01",
            "OpenedBy": "46c6f9efa9fe198101ddf5eed9adf6e7",
            "Priority": "5 - Planning",
            "State": "1",
            "Summary": "Trouble getting to Oregon mail server"
        }
    },
    "Ticket": {
        "Active": "true",
        "CreatedOn": "2020-01-26 00:42:29",
        "Creator": "id",
        "ID": "id",
        "Number": "INC0000039",
        "OpenedAt": "2020-01-26 00:41:01",
        "OpenedBy": "46c6f9efa9fe198101ddf5eed9adf6e7",
        "Priority": "5 - Planning",
        "State": "1",
        "Summary": "Trouble getting to Oregon mail server"
    }
}
```

##### Human Readable Output
### ServiceNow ticket
|System ID|Number|Impact|Urgency|Severity|Priority|State|Created On|Created By|Active|Description|Opened At|SLA Due|Short Description|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| id | INC0000039 | 3 - Low | 3 - Low | 3 - Low | 5 - Planning | 1 - New | 2020-01-26 00:42:29 | admin | true | Unable to access Oregon mail server. Is it down? | 2020-01-26 00:41:01 | 2020-02-16 00:41:01 | Trouble getting to Oregon mail server |


### servicenow-create-ticket
***
Create new ServiceNow ticket


##### Base Command

`servicenow-create-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| short_description | Short description of the ticket | Optional | 
| ticket_type | Ticket type | Optional | 
| urgency | Ticket urgency | Optional | 
| severity | Ticket severity | Optional | 
| impact | Ticket impact | Optional | 
| active | Set ticket as Active | Optional | 
| activity_due | Set ticket ActivityDue - format &quot;2016-07-02 21:51:11&quot; | Optional | 
| additional_assignee_list | List of assigned users to the ticket | Optional | 
| approval_history | Ticket history approval | Optional | 
| approval_set | Set ticket ApprovalSet - format &quot;2016-07-02 21:51:11&quot; | Optional | 
| assigned_to | To whom the ticket is assigned | Optional | 
| business_duration | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| business_service | Business service | Optional | 
| business_stc | Business source | Optional | 
| calendar_duration | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| caller_id | UID Format | Optional | 
| category | Category of ticket | Optional | 
| caused_by | UID Format | Optional | 
| close_code | Ticket&#x27;s close code | Optional | 
| close_notes | Close notes of the ticket | Optional | 
| closed_at | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| closed_by | User who closed the ticket | Optional | 
| cmdb_ci | UID Format | Optional | 
| comments | Format type journal input | Optional | 
| comments_and_work_notes | Format type journal input | Optional | 
| company | UID Format | Optional | 
| contact_type | Contact type | Optional | 
| correlation_display | Correlation display | Optional | 
| correlation_id | Correlation id | Optional | 
| delivery_plan | UID Format | Optional | 
| display | If you want to display comments, work_notes... | Optional | 
| description | Ticket description | Optional | 
| due_date | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| escalation | Escalation | Optional | 
| expected_start | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| follow_up | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| group_list | UID format list | Optional | 
| knowledge | Is the ticket solved in the knowledge base | Optional | 
| location | Location of the ticket | Optional | 
| made_sla | SLA of the ticket | Optional | 
| notify | Notify about this ticket | Optional | 
| order | Order number | Optional | 
| parent | UID Format | Optional | 
| parent_incident | UID Format | Optional | 
| problem_id | UID Format | Optional | 
| reassignment_count | How many users included in this ticket before | Optional | 
| reopen_count | How many time the ticket has been reopened | Optional | 
| resolved_at | Resolving time, Format: YYYY-MM-DD HH:MM:SS | Optional | 
| resolved_by | UID Format | Optional | 
| rfc | UID | Optional | 
| sla_due | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| subcategory | Subcategory | Optional | 
| sys_updated_by | Last updated by | Optional | 
| sys_updated_on | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| user_input | Input from the end user | Optional | 
| watch_list | A list of watched tickets | Optional | 
| work_end | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| work_notes | Format journal list | Optional | 
| work_notes_list | List with UIDs | Optional | 
| work_start | Date when started to work on the ticket | Optional | 
| assignment_group | Set AssignmentGroup - sys_id of group | Optional | 
| incident_state | integer | Optional | 
| number | Ticket number | Optional | 
| priority | Priority of the ticket | Optional | 
| template | Template name to use as a base to create new tickets. | Optional | 
| custom_fields | Custom(user defined) fields in the format: fieldname1=value;fieldname2=value; custom fields start with a &quot;u_&quot;. | Optional | 
| change_type | Type of Change Request ticket | Optional | 
| state | State of the ticket, e.g., &quot;Closed&quot; or &quot;7&quot; or &quot;7 - Closed&quot;. | Optional | 
| opened_at |  Ticket opening time, Format: YYYY-MM-DD HH:MM:SS | Optional | 
| caller | Caller system ID | Optional | 
| approval | Ticket approval | Optional | 
| additional_fields | Additional fields in the format: fieldname1=value;fieldname2=value; | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | string | ServiceNow ticket ID | 
| ServiceNow.Ticket.OpenedBy | string | ServiceNow ticket opener ID | 
| ServiceNow.Ticket.CreatedOn | date | ServiceNow ticket creation date. | 
| ServiceNow.Ticket.Assignee | string | ServiceNow ticket assignee ID | 
| ServiceNow.Ticket.State | string | ServiceNow ticket state | 
| ServiceNow.Ticket.Summary | string | ServiceNow ticket short summary | 
| ServiceNow.Ticket.Number | string | ServiceNow ticket number | 
| ServiceNow.Ticket.Active | boolean | ServiceNow ticket active | 
| ServiceNow.Ticket.AdditionalComments | string | ServiceNow ticket comments | 
| ServiceNow.Ticket.Priority | string | ServiceNow ticket priority | 
| ServiceNow.Ticket.OpenedAt | date | ServiceNow ticket opening time | 
| ServiceNow.Ticket.ResolvedBy | string | ServiceNow ticket resolver ID | 
| ServiceNow.Ticket.CloseCode | string | ServiceNow ticket close code | 


##### Command Example
```!servicenow-create-ticket active=true severity="2 - Medium"```

##### Context Example
```
{
    "ServiceNow": {
        "Ticket": {
            "Active": "true",
            "CreatedOn": "2020-04-26 15:51:29",
            "Creator": "id",
            "ID": "id",
            "Number": "INC0010001",
            "OpenedAt": "2020-04-26 15:51:29",
            "OpenedBy": "id",
            "Priority": "5 - Planning",
            "State": "1"
        }
    },
    "Ticket": {
        "Active": "true",
        "CreatedOn": "2020-04-26 15:51:29",
        "Creator": "id",
        "ID": "id",
        "Number": "INC0010001",
        "OpenedAt": "2020-04-26 15:51:29",
        "OpenedBy": "id",
        "Priority": "5 - Planning",
        "State": "1"
    }
}
```

##### Human Readable Output
### ServiceNow ticket was created successfully.
|System ID|Number|Impact|Urgency|Severity|Priority|State|Created On|Created By|Active|Opened At|
|---|---|---|---|---|---|---|---|---|---|---|
| id | INC0010001 | 3 - Low | 3 - Low | 2 - Medium | 5 - Planning | 1 - New | 2020-04-26 15:51:29 | admin | true | 2020-04-26 15:51:29 |


### servicenow-update-ticket
***
Update specific ticket


##### Base Command

`servicenow-update-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| short_description | Short description of the ticket | Optional | 
| ticket_type | Ticket type | Optional | 
| urgency | Ticket urgency | Optional | 
| severity | Ticket severity | Optional | 
| impact | Ticket impact | Optional | 
| active | Does the ticket active(true/false) | Optional | 
| activity_due | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| additional_assignee_list | List of assigned users to the ticket | Optional | 
| approval_history | Ticket history approval | Optional | 
| approval_set | Set ticket ApprovalSet - format &quot;2016-07-02 21:51:11&quot; | Optional | 
| assigned_to | To whom the ticket is assigned | Optional | 
| business_duration | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| business_service | Business service | Optional | 
| business_stc | Business source | Optional | 
| calendar_duration | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| caller_id | UID Format | Optional | 
| category | Category name | Optional | 
| caused_by | UID Format | Optional | 
| close_code | Ticket&#x27;s close code | Optional | 
| close_notes | Close notes of the ticket | Optional | 
| closed_at | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| closed_by | User who closed the ticket | Optional | 
| cmdb_ci | UID Format | Optional | 
| comments | Format type journal input | Optional | 
| comments_and_work_notes | Format type journal input | Optional | 
| company | UID Format | Optional | 
| contact_type | Contact type | Optional | 
| correlation_display | Correlation display | Optional | 
| correlation_id | Correlation id | Optional | 
| delivery_plan | UID Format | Optional | 
| display | If you want to display comments, work_notes... | Optional | 
| description | Ticket description | Optional | 
| due_date | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| escalation | Escalation | Optional | 
| expected_start | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| follow_up | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| group_list | UID format list | Optional | 
| knowledge | Is the ticket solved in the knowledge base | Optional | 
| location | Location of the ticket | Optional | 
| made_sla | SLA of the ticket | Optional | 
| notify | Notify about this ticket | Optional | 
| order | Order number | Optional | 
| parent | UID Format | Optional | 
| parent_incident | UID Format | Optional | 
| problem_id | UID Format | Optional | 
| reassignment_count | How many users included in this ticket before | Optional | 
| reopen_count | How many time the ticket has been reopened | Optional | 
| resolved_at | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| resolved_by | UID Format | Optional | 
| rfc | UID | Optional | 
| sla_due | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| subcategory | Subcategory | Optional | 
| sys_updated_by | Last updated by | Optional | 
| sys_updated_on | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| user_input | Input from the end user | Optional | 
| watch_list | A list of watched tickets | Optional | 
| work_end | Format: YYYY-MM-DD HH:MM:SS | Optional | 
| work_notes | Format journal list | Optional | 
| work_notes_list | List with UIDs | Optional | 
| work_start | Date when started to work on the ticket | Optional | 
| assignment_group | UID | Optional | 
| incident_state | integer | Optional | 
| number | Ticket number | Optional | 
| priority | Priority of the ticket | Optional | 
| id | System ID of the ticket to update | Required | 
| custom_fields | Custom(user defined) fields in the format: fieldname1=value;fieldname2=value; custom fields start with a &quot;u_&quot;. | Optional | 
| change_type | Type of Change Request ticket | Optional | 
| state | State of the ticket, e.g., &quot;Closed&quot; or &quot;7&quot; or &quot;7 - Closed&quot;. | Optional | 
| caller | Caller system ID | Optional | 
| approval | Ticket approval | Optional | 
| additional_fields | Additional fields in the format: fieldname1=value;fieldname2=value; | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### servicenow-delete-ticket
***
Delete a ticket from ServiceNow


##### Base Command

`servicenow-delete-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID | Required | 
| ticket_type | Ticket type | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!servicenow-delete-ticket id=id```

##### Context Example
```
{}
```

##### Human Readable Output
Ticket with ID id was successfully deleted.

### servicenow-query-tickets
***
Retrieve ticket info with a query


##### Base Command

`servicenow-query-tickets`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit for how many tickets to retrieve | Optional | 
| ticket_type | Ticket type | Optional | 
| query | The query to run. To learn about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| offset | Starting record index to begin retrieving records from | Optional | 
| additional_fields | Additional fields to present in the war room entry and incident context. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | string | The unique ticket identifier. | 
| Ticket.Creator | string | A string field that indicates the user who created the ticket. | 
| Ticket.CreatedOn | date | The date and time when the ticket was created. | 
| Ticket.Assignee | string | Specifies the user assigned to complete the ticket. By default, this field uses a reference qualifier to only display users with the itil role. | 
| Ticket.State | string | Status of the ticket. | 
| Ticket.Summary | string | A human\-readable title for the record. | 
| Ticket.Number | string | The display value of the ticket. | 
| Ticket.Active | boolean | Specifies whether work is still being done on a task or whether the work for the task is complete. | 
| Ticket.AdditionalComments | Unknown | Comments about the task record. | 
| Ticket.Priority | string | Specifies how high a priority the ticket should be for the assignee. | 
| Ticket.OpenedAt | date | The date and time when the ticket was opened for the first time. | 
| Ticket.Escalation | string | Indicates how long the ticket has been open. | 


##### Command Example
```!servicenow-query-tickets limit="3" query="impact<2^short_descriptionISNOTEMPTY" ticket_type="incident"```

##### Context Example
```
{
    "ServiceNow": {
        "Ticket": [
            {
                "Active": "false",
                "Assignee": "id",
                "CloseCode": "Closed/Resolved by Caller",
                "CreatedOn": "2018-08-24 18:24:13",
                "Creator": "id",
                "ID": "id",
                "Number": "INC0000001",
                "OpenedAt": "2020-01-23 23:09:51",
                "OpenedBy": "id",
                "Priority": "1 - Critical",
                "ResolvedBy": "id",
                "State": "7",
                "Summary": "Can't read email"
            },
            {
                "Active": "true",
                "Assignee": "id",
                "CreatedOn": "2018-08-13 22:30:06",
                "Creator": "id",
                "ID": "id",
                "Number": "INC0000002",
                "OpenedAt": "2020-01-17 23:07:12",
                "OpenedBy": "id",
                "Priority": "1 - Critical",
                "State": "3",
                "Summary": "Network file shares access issue"
            },
            {
                "Active": "true",
                "Assignee": "id",
                "CreatedOn": "2018-08-28 14:41:46",
                "Creator": "id",
                "ID": "id",
                "Number": "INC0000003",
                "OpenedAt": "2020-01-24 23:07:30",
                "OpenedBy": "id",
                "Priority": "1 - Critical",
                "State": "2",
                "Summary": "Wireless access is down in my area"
            }
        ]
    },
    "Ticket": [
        {
            "Active": "false",
            "Assignee": "id",
            "CloseCode": "Closed/Resolved by Caller",
            "CreatedOn": "2018-08-24 18:24:13",
            "Creator": "id",
            "ID": "id",
            "Number": "INC0000001",
            "OpenedAt": "2020-01-23 23:09:51",
            "OpenedBy": "id",
            "Priority": "1 - Critical",
            "ResolvedBy": "id",
            "State": "7",
            "Summary": "Can't read email"
        },
        {
            "Active": "true",
            "Assignee": "id",
            "CreatedOn": "2018-08-13 22:30:06",
            "Creator": "id",
            "ID": "id",
            "Number": "INC0000002",
            "OpenedAt": "2020-01-17 23:07:12",
            "OpenedBy": "id",
            "Priority": "1 - Critical",
            "State": "3",
            "Summary": "Network file shares access issue"
        },
        {
            "Active": "true",
            "Assignee": "id",
            "CreatedOn": "2018-08-28 14:41:46",
            "Creator": "id",
            "ID": "id",
            "Number": "INC0000003",
            "OpenedAt": "2020-01-24 23:07:30",
            "OpenedBy": "id",
            "Priority": "1 - Critical",
            "State": "2",
            "Summary": "Wireless access is down in my area"
        }
    ]
}
```

##### Human Readable Output
### ServiceNow tickets
|System ID|Number|Impact|Urgency|Severity|Priority|State|Created On|Created By|Active|Close Notes|Close Code|Description|Opened At|Resolved By|Resolved At|Short Description|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| id | INC0000001 | 1 - High | 1 - High | 1 - High | 1 - Critical | 7 - Closed | 2018-08-24 18:24:13 | pat | false | Closed before close notes were made mandatory<br>		 | Closed/Resolved by Caller | User can't access email on mail.company.com.<br>		 | 2020-01-23 23:09:51 | id | 2020-04-24 19:56:12 | Can't read email |
| id | INC0000002 | 1 - High | 1 - High | 1 - High | 1 - Critical | 3 - On Hold | 2018-08-13 22:30:06 | pat | true |  |  | User can't get to any of his files on the file server. | 2020-01-17 23:07:12 |  |  | Network file shares access issue |
| id | INC0000003 | 1 - High | 1 - High | 1 - High | 1 - Critical | 2 - In Progress | 2018-08-28 14:41:46 | admin | true |  |  | I just moved from floor 2 to floor 3 and my laptop cannot connect to any wireless network. | 2020-01-24 23:07:30 |  |  | Wireless access is down in my area |


### servicenow-add-link
***
Add a link to specific ticket


##### Base Command

`servicenow-add-link`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID | Required | 
| ticket_type | Ticket type | Optional | 
| link | The actual link to publish in ServiceNow ticket, valid url format, like http://www.demisto.com | Required | 
| post-as-comment | Publish the link as comment on the ticket, if false will publish the link as WorkNote, format bool | Optional | 
| text | The text to represent the link | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!servicenow-add-link id=id link="http://www.demisto.com" text=demsito_link```

##### Context Example
```
{}
```

##### Human Readable Output
### Link successfully added to ServiceNow ticket
**No entries.**


### servicenow-add-comment
***
Add comment to specific ticket by providing ticket id


##### Base Command

`servicenow-add-comment`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID | Required | 
| ticket_type | Ticket type | Optional | 
| comment | Comment to add | Required | 
| post-as-comment | Specify to publish the note as comment on the ticket. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!servicenow-add-comment id=id comment="Nice work!"```

##### Context Example
```
{}
```

##### Human Readable Output
### Comment successfully added to ServiceNow ticket
**No entries.**


### servicenow-upload-file
***
Upload a file to a specific ticket


##### Base Command

`servicenow-upload-file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID | Required | 
| ticket_type | Ticket type | Optional | 
| file_id | War-room entry ID that includes the file | Required | 
| file_name | Filename of uploaded file to override the existing file name in entry | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.File.Filename | string | Name of the file | 
| ServiceNow.Ticket.File.Link | string | Download link for the file | 
| ServiceNow.Ticket.File.SystemID | string | System ID of the file | 


##### Command Example
``` ```

##### Human Readable Output


### servicenow-get-record
***
Retrieve record information by specific record ID


##### Base Command

`servicenow-get-record`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Record system ID | Required | 
| fields | Comma separated table fields to display and output to the context, e.g name,tag,company. ID field is added by default. | Optional | 
| table_name | The name of the table to get the record from | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Record.ID | string | The unique record identifier for the record. | 
| ServiceNow.Record.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Record.UpdatedAt | date | A time\-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Record.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Record.CreatedOn | date | time\-stamp field that indicates when a record was created. | 


##### Command Example
```!servicenow-get-record table_name=alm_asset id=id fields=asset_tag,sys_updated_by,display_name```

##### Context Example
```
{
    "ServiceNow": {
        "Record": {
            "ID": "id",
            "asset_tag": "P1000479",
            "display_name": "P1000479 - Apple MacBook Pro 15\"",
            "sys_updated_by": "system"
        }
    }
}
```

##### Human Readable Output
### ServiceNow record
|ID|asset_tag|display_name|sys_updated_by|
|---|---|---|---|
| id | P1000479 | P1000479 - Apple MacBook Pro 15" | system |


### servicenow-query-table
***
Query a specified table in ServiceNow


##### Base Command

`servicenow-query-table`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table to query | Required | 
| limit | Limit for how many tickets to retrieve | Optional | 
| query | The query to run. For more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| fields | Comma separated table fields to display and output to the context, e.g name,tag,company. ID field is added by default. | Optional | 
| offset | Starting record index to begin retrieving records from | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Results.ID | string | The unique record identifier for the record. | 
| ServiceNow.Results.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Results.UpdatedAt | date | A time\-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Results.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Results.CreatedOn | date | time\-stamp field that indicates when a record was created. | 


##### Command Example
```!servicenow-query-table table_name=alm_asset fields=asset_tag,sys_updated_by,display_name query=display_nameCONTAINSMacBook limit=4```

##### Context Example
```
{
    "ServiceNow": {
        "Record": [
            {
                "ID": "id",
                "asset_tag": "P1000807",
                "display_name": "P1000807 - Apple MacBook Pro 17\"",
                "sys_updated_by": "system"
            },
            {
                "ID": "id",
                "asset_tag": "P1000637",
                "display_name": "P1000637 - Apple MacBook Air 13\"",
                "sys_updated_by": "system"
            },
            {
                "ID": "id",
                "asset_tag": "P1000412",
                "display_name": "P1000412 - Apple MacBook Pro 17\"",
                "sys_updated_by": "system"
            },
            {
                "ID": "id",
                "asset_tag": "P1000563",
                "display_name": "P1000563 - Apple MacBook Pro 15\"",
                "sys_updated_by": "system"
            }
        ]
    }
}
```

##### Human Readable Output
### ServiceNow records
|ID|asset_tag|display_name|sys_updated_by|
|---|---|---|---|
| id | P1000807 | P1000807 - Apple MacBook Pro 17" | system |
| id | P1000637 | P1000637 - Apple MacBook Air 13" | system |
| id | P1000412 | P1000412 - Apple MacBook Pro 17" | system |
| id | P1000563 | P1000563 - Apple MacBook Pro 15" | system |


### servicenow-create-record
***
Create a new record in a specified ServiceNow table


##### Base Command

`servicenow-create-record`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table to create a record in. | Required | 
| fields | Fields and their values to create the record with, in the format: fieldname1=value;fieldname2=value;... | Optional | 
| custom_fields | Custom(user defined) fields in the format: fieldname1=value;fieldname2=value;... | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Record.ID | string | The unique record identifier for the record. | 
| ServiceNow.Record.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Record.UpdatedAt | date | A time\-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Record.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Record.CreatedOn | date | time\-stamp field that indicates when a record was created. | 


##### Command Example
```!servicenow-create-record table_name=alm_asset fields="asset_tag=P4325432"```

##### Context Example
```
{
    "ServiceNow": {
        "Record": {
            "CreatedAt": "2020-04-26 15:51:54",
            "CreatedBy": "admin",
            "ID": "id",
            "UpdatedAt": "2020-04-26 15:51:54",
            "UpdatedBy": "admin"
        }
    }
}
```

##### Human Readable Output
### ServiceNow record created successfully
|CreatedAt|CreatedBy|ID|UpdatedAt|UpdatedBy|
|---|---|---|---|---|
| 2020-04-26 15:51:54 | admin | id | 2020-04-26 15:51:54 | admin |


### servicenow-update-record
***
Update a record in a specified ServiceNow table


##### Base Command

`servicenow-update-record`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table to update the record in | Required | 
| id | The system ID of the ticket to update | Required | 
| fields | Fields and their values to update in the record, in the format: fieldname1=value;fieldname2=value;... | Optional | 
| custom_fields | Custom(User defined) fields and their values to update in the record, in the format: fieldname1=value;fieldname2=value;... | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Record.ID | string | The unique record identifier for the record. | 
| ServiceNow.Record.UpdatedBy | string | A string field that indicates the user who most recently updated the record. | 
| ServiceNow.Record.UpdatedAt | date | A time\-stamp field that indicates the date and time of the most recent update. | 
| ServiceNow.Record.CreatedBy | string | A string field that indicates the user who created the record. | 
| ServiceNow.Record.CreatedOn | date | time\-stamp field that indicates when a record was created. | 


##### Command Example
```!servicenow-update-record table_name=alm_asset id=id custom_fields="display_name=test4"```

##### Context Example
```
{
    "ServiceNow": {
        "Record": {
            "CreatedAt": "2019-07-16 08:14:21",
            "CreatedBy": "admin",
            "ID": "id",
            "UpdatedAt": "2020-04-26 08:25:03",
            "UpdatedBy": "system"
        }
    }
}
```

##### Human Readable Output
### ServiceNow record with ID 00a96c0d3790200044e0bfc8bcbe5dc3 updated successfully
|CreatedAt|CreatedBy|ID|UpdatedAt|UpdatedBy|
|---|---|---|---|---|
| 2019-07-16 08:14:21 | admin | id | 2020-04-26 08:25:03 | system |


### servicenow-delete-record
***
Delete a record in a specified ServiceNow table


##### Base Command

`servicenow-delete-record`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The table name | Required | 
| id | The system ID of the ticket to delete | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!servicenow-delete-record table_name=alm_asset id=id```

##### Context Example
```
{}
```

##### Human Readable Output
ServiceNow record with ID id was successfully deleted.

### servicenow-list-table-fields
***
List API fields for a specified ServiceNow table


##### Base Command

`servicenow-list-table-fields`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Field | string | Table API field name | 


##### Command Example
```!servicenow-list-table-fields table_name=alm_asset```

##### Context Example
```
{
    "ServiceNow": {
        "Field": [
            {
                "Name": "parent"
            },
            {
                "Name": "skip_sync"
            },
            {
                "Name": "residual_date"
            },
            {
                "Name": "residual"
            },
            {
                "Name": "sys_updated_on"
            },
            {
                "Name": "request_line"
            },
            {
                "Name": "sys_updated_by"
            },
            {
                "Name": "due_in"
            },
            {
                "Name": "model_category"
            },
            {
                "Name": "sys_created_on"
            },
            {
                "Name": "sys_domain"
            },
            {
                "Name": "disposal_reason"
            },
            {
                "Name": "model"
            },
            {
                "Name": "install_date"
            },
            {
                "Name": "gl_account"
            },
            {
                "Name": "invoice_number"
            },
            {
                "Name": "sys_created_by"
            },
            {
                "Name": "warranty_expiration"
            },
            {
                "Name": "depreciated_amount"
            },
            {
                "Name": "substatus"
            },
            {
                "Name": "pre_allocated"
            },
            {
                "Name": "owned_by"
            },
            {
                "Name": "checked_out"
            },
            {
                "Name": "display_name"
            },
            {
                "Name": "sys_domain_path"
            },
            {
                "Name": "delivery_date"
            },
            {
                "Name": "retirement_date"
            },
            {
                "Name": "beneficiary"
            },
            {
                "Name": "install_status"
            },
            {
                "Name": "cost_center"
            },
            {
                "Name": "supported_by"
            },
            {
                "Name": "assigned"
            },
            {
                "Name": "purchase_date"
            },
            {
                "Name": "work_notes"
            },
            {
                "Name": "managed_by"
            },
            {
                "Name": "sys_class_name"
            },
            {
                "Name": "sys_id"
            },
            {
                "Name": "po_number"
            },
            {
                "Name": "stockroom"
            },
            {
                "Name": "checked_in"
            },
            {
                "Name": "resale_price"
            },
            {
                "Name": "vendor"
            },
            {
                "Name": "company"
            },
            {
                "Name": "retired"
            },
            {
                "Name": "justification"
            },
            {
                "Name": "department"
            },
            {
                "Name": "expenditure_type"
            },
            {
                "Name": "depreciation"
            },
            {
                "Name": "assigned_to"
            },
            {
                "Name": "depreciation_date"
            },
            {
                "Name": "old_status"
            },
            {
                "Name": "comments"
            },
            {
                "Name": "cost"
            },
            {
                "Name": "quantity"
            },
            {
                "Name": "acquisition_method"
            },
            {
                "Name": "ci"
            },
            {
                "Name": "sys_mod_count"
            },
            {
                "Name": "old_substatus"
            },
            {
                "Name": "sys_tags"
            },
            {
                "Name": "order_date"
            },
            {
                "Name": "support_group"
            },
            {
                "Name": "reserved_for"
            },
            {
                "Name": "due"
            },
            {
                "Name": "location"
            },
            {
                "Name": "lease_id"
            },
            {
                "Name": "salvage_value"
            }
        ]
    }
}
```

##### Human Readable Output
### ServiceNow Table fields - alm_asset
|Name|
|---|
| parent |
| skip_sync |
| residual_date |
| residual |
| sys_updated_on |
| request_line |
| sys_updated_by |
| due_in |
| model_category |
| sys_created_on |
| sys_domain |
| disposal_reason |
| model |
| install_date |
| gl_account |
| invoice_number |
| sys_created_by |
| warranty_expiration |
| depreciated_amount |
| substatus |
| pre_allocated |
| owned_by |
| checked_out |
| display_name |
| sys_domain_path |
| delivery_date |
| retirement_date |
| beneficiary |
| install_status |
| cost_center |
| supported_by |
| assigned |
| purchase_date |
| work_notes |
| managed_by |
| sys_class_name |
| sys_id |
| po_number |
| stockroom |
| checked_in |
| resale_price |
| vendor |
| company |
| retired |
| justification |
| department |
| expenditure_type |
| depreciation |
| assigned_to |
| depreciation_date |
| old_status |
| comments |
| cost |
| quantity |
| acquisition_method |
| ci |
| sys_mod_count |
| old_substatus |
| sys_tags |
| order_date |
| support_group |
| reserved_for |
| due |
| location |
| lease_id |
| salvage_value |


### servicenow-query-computers
***
Query the cmdb_ci_computer table in ServiceNow


##### Base Command

`servicenow-query-computers`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer_id | Query by computer sys_id | Optional | 
| computer_name | Query by computer name | Optional | 
| query | Query by specified query, for more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| asset_tag | Query by asset tag | Optional | 
| limit | Query results limit | Optional | 
| offset | Starting record index to begin retrieving records from | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Computer.ID | string | Computer sys\_id | 
| ServiceNow.Computer.AssetTag | string | Computer Asset tag | 
| ServiceNow.Computer.Name | string | Computer name | 
| ServiceNow.Computer.DisplayName | string | Computer display name | 
| ServiceNow.Computer.SupportGroup | string | Computer support group | 
| ServiceNow.Computer.OperatingSystem | string | Computer operating system | 
| ServiceNow.Computer.Company | string | Computer company sys\_id | 
| ServiceNow.Computer.AssignedTo | string | Computer assigned to user sys\_id | 
| ServiceNow.Computer.State | string | Computer state | 
| ServiceNow.Computer.Cost | string | Computer cost | 
| ServiceNow.Computer.Comments | string | Computer comments | 


##### Command Example
```!servicenow-query-computers asset_tag=P1000503```

##### Context Example
```
{
    "ServiceNow": {
        "Computer": {
            "AssetTag": "P1000503",
            "AssignedTo": "id",
            "Company": "id",
            "Cost": "1799.99 USD",
            "DisplayName": "P1000503 - MacBook Pro 15\"",
            "ID": "id",
            "Name": "MacBook Pro 15\"",
            "OperatingSystem": "Mac OS 10 (OS/X)",
            "State": "In use"
        }
    }
}
```

##### Human Readable Output
### ServiceNow Computers
|ID|Asset Tag|Name|Display Name|Operating System|Company|Assigned To|State|Cost|
|---|---|---|---|---|---|---|---|---|
| id | P1000503 | MacBook Pro 15" | P1000503 - MacBook Pro 15" | Mac OS 10 (OS/X) | 81fbfe03ac1d55eb286d832de58ae1fd | 92826bf03710200044e0bfc8bcbe5dbb | In use | 1799.99 USD |


### servicenow-query-groups
***
Query the sys_user_group table in ServiceNow


##### Base Command

`servicenow-query-groups`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Query by group sys_id | Optional | 
| group_name | Query by group name | Optional | 
| query | Query by specified query, for more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| limit | Query results limit | Optional | 
| offset | Starting record index to begin retrieving records from | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Group.ID | string | Group sys\_id | 
| ServiceNow.Group.Description | string | Group description | 
| ServiceNow.Group.Name | string | Group name | 
| ServiceNow.Group.Manager | string | Group manager sys\_id | 
| ServiceNow.Group.Updated | date | Group update time | 


##### Command Example
```!servicenow-query-groups group_name=test1```

##### Context Example
```
{}
```

##### Human Readable Output
No groups found.

### servicenow-query-users
***
Query the sys_user table in ServiceNow


##### Base Command

`servicenow-query-users`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Query by user sys_id | Optional | 
| user_name | Query by username | Optional | 
| query | Query by specified query, for more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/istanbul-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| limit | Query results limit | Optional | 
| offset | Starting record index to begin retrieving records from | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.User.ID | string | User sys\_id | 
| ServiceNow.User.Name | string | User name \(first \+ last\) | 
| ServiceNow.User.UserName | string | User username | 
| ServiceNow.User.Email | string | User email | 
| ServiceNow.User.Created | date | User creation time | 
| ServiceNow.User.Updated | date | User update time | 


##### Command Example
```!servicenow-query-users user_name=sean.bonnet```

##### Context Example
```
{
    "ServiceNow": {
        "User": {
            "Created": "2012-02-18 03:04:50",
            "Email": "sean.bonnet@example.com",
            "ID": "id",
            "Name": "Sean Bonnet",
            "Updated": "2020-04-25 19:01:46",
            "UserName": "sean.bonnet"
        }
    }
}
```

##### Human Readable Output
### ServiceNow Users
|ID|Name|User Name|Email|Created|Updated|
|---|---|---|---|---|---|
| id | Sean Bonnet | sean.bonnet | sean.bonnet@example.com | 2012-02-18 03:04:50 | 2020-04-25 19:01:46 |


### servicenow-get-table-name
***
Get table names by a label to use in commands


##### Base Command

`servicenow-get-table-name`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label | The table label, e.g Asset, Incident, IP address etc. | Required | 
| limit | Results limit | Optional | 
| offset | Starting record index to begin retrieving records from | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Table.ID | string | Table system ID | 
| ServiceNow.Table.Name | string | Table name to use in commands, e.g alm\_asset | 
| ServiceNow.Table.SystemName | string | Table system name, e.g Asset | 


##### Command Example
```!servicenow-get-table-name label=ACE```

##### Context Example
```
{
    "ServiceNow": {
        "Table": {
            "ID": "id",
            "Name": "cmdb_ci_lb_ace",
            "SystemName": "CMDB CI Lb Ace"
        }
    }
}
```

##### Human Readable Output
### ServiceNow Tables for label - ACE
|ID|Name|System Name|
|---|---|---|
| id | cmdb_ci_lb_ace | CMDB CI Lb Ace |


### servicenow-get-ticket-notes
***
Get notes from the specified ServiceNow ticket - Read permissions are required for the sys_journal_field table.


##### Base Command

`servicenow-get-ticket-notes`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket System ID | Required | 
| limit | Limit for the ticket notes | Optional | 
| offset | Offset of the ticket notes | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.Ticket.ID | string | Ticket ID | 
| ServiceNow.Ticket.Note.Value | unknown | Ticket note value | 
| ServiceNow.Ticket.Note.CreatedOn | date | Ticket note created on | 
| ServiceNow.Ticket.Note.CreatedBy | string | Ticket note created by | 
| ServiceNow.Ticket.Note.Type | string | Ticket note type | 


##### Command Example
```!servicenow-get-ticket-notes id=id```

##### Context Example
```
{
    "ServiceNow": {
        "Ticket": {
            "ID": "id",
            "Note": [
                {
                    "CreatedBy": "admin",
                    "CreatedOn": "2020-01-26 00:42:29",
                    "Type": "Comment",
                    "Value": "Routing from San Diego to the Oregon mail server appears to be\n\t\t\tgetting packet lose!\n\t\t"
                }
            ]
        }
    }
}
```

##### Human Readable Output
### ServiceNow notes for ticket id
|Value|Created On|Created By|Type|
|---|---|---|---|
| Routing from San Diego to the Oregon mail server appears to be<br>			getting packet lose!<br>		 | 2020-01-26 00:42:29 | admin | Comment |


### servicenow-document-route-to-queue
***
Document a route to a queue. Requires an installation of the Advanced Work Assignments plugin. An active queue and service channel to the designated table.


##### Base Command

`servicenow-document-route-to-queue`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_id | Queue ID. Can be retrieved using &quot;!servicenow-query-table table_name=awa_queue fields=name,number,order&quot; | Required | 
| document_table | Document table. | Optional | 
| document_id | Document ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNow.WorkItem.WorkItemID | String | Unique ID of the work item assigned to the queue. | 
| ServiceNow.WorkItem.DocumentTable | String | Name of the table associated with the document | 
| ServiceNow.WorkItem.DocumentID | String | Unique ID of the document to be routed to the queue. | 
| ServiceNow.WorkItem.QueueID | String | Unique ID of the queue on which to route a document. | 
| ServiceNow.WorkItem.DisplayName | String | Name of the document to be routed by this work item, e.g., case record. | 


##### Command Example
```!servicenow-document-route-to-queue queue_id=id document_id=id```

##### Context Example
```
{
    "ServiceNow": {
        "WorkItem": {
            "DisplayName": "Incident: INC0000060",
            "DocumentID": "id",
            "DocumentTable": "incident",
            "QueueID": "id",
            "WorkItemID": "id"
        }
    }
}
```

##### Human Readable Output
### ServiceNow Queue
|Display Name|Document ID|Document Table|Queue ID|Work Item ID|
|---|---|---|---|---|
| Incident: INC0000060 | id | incident | id | id |

