Service management suite that comprises ticketing, workflow automation, and notification.
This integration was integrated and tested with version 7.x of OTRS
## Configure OTRSv2 on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OTRSv2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | OTRS Server URL \(e.g. https://demisto.managed\-otrs.com\) | True |
| credentials | OTRS Credentials | True |
| unsecure | Trust any certificate \(unsecure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| fetch_queue | Queues to fetch tickets from  \(&quot;Any&quot; fetches from all queues. CSV supported, e.g., Misc,Raw\) | False |
| fetch_priority | Fetch tickets in priority | False |
| fetch_time | First fetch timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### otrs-get-ticket
***
Retrieves details for an OTRS ticket by ticket ID or ticket number.


##### Base Command

`otrs-get-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | Ticket ID of the ticket to get details of | Optional | 
| ticket_number | Ticket Number of the ticket to get details of | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OTRS.Ticket.ID | string | Ticket ID | 
| OTRS.Ticket.Created | date | Ticket creation date | 
| OTRS.Ticket.CustomerUser | string | Customer user related to ticket | 
| OTRS.Ticket.Owner | string | Ticket owner | 
| OTRS.Ticket.Priority | string | Ticket priority | 
| OTRS.Ticket.Queue | string | Queue the ticket is in | 
| OTRS.Ticket.State | string | Ticket state | 
| OTRS.Ticket.Title | string | Ticket title | 
| OTRS.Ticket.Type | string | Ticket type | 
| OTRS.Ticket.DynamicField | string | Ticket dynamic fields | 
| OTRS.Ticket.Article.Subject | string | Ticket article subject | 
| OTRS.Ticket.Article.Body | string | Ticket article body | 
| OTRS.Ticket.Article.CreatedTime | date | Ticket article creation time | 
| OTRS.Ticket.Article.ContentType | string | Ticket article content type | 
| OTRS.Ticket.Article.From | string | Ticket article sender | 
| OTRS.Ticket.Article.ID | string | Ticket article ID | 
| OTRS.Ticket.Article.Attachment.Name | string | Ticket article attachment file name | 
| OTRS.Ticket.Article.Attachment.Size | number | Ticket article attachment file size | 
| OTRS.Ticket.Article.Attachment.ContentType | string | Ticket article attachment file content type | 
| OTRS.Ticket.Lock | string | Is the ticket locked or unlocked | 
| File.Size | number | Size of the file attachment | 
| File.SHA1 | string | SHA\-1 of the file attachment | 
| File.SHA256 | string | SHA\-256 of the file attachment | 
| File.Name | string | Attachment file name | 
| File.SSDeep | string | Attachment file SSDeep | 
| File.EntryID | string | Attachment file entry ID | 
| File.Info | string | Attachment file information | 
| File.Type | string | Attachment file type | 
| File.MD5 | string | Attachment file MD5 | 
| File.Extension | string | Attachment file extension | 
| OTRS.Ticket.TicketNumber | string | Ticket number | 


##### Command Example
``` ```

##### Human Readable Output


### otrs-search-ticket
***
Search for an OTRS ticket using search filters


##### Base Command

`otrs-search-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Ticket States to filter by in CSV format (e.g., New,Open) | Optional | 
| created_before | Filter for a ticket created before this date. Given in format &quot;&lt;number&gt; &lt;time unit&gt;&quot;, e.g. 1 day, 30 minutes, 2 weeks, 6 months, 1 year | Optional | 
| created_after | Filter for a ticket created after this date. Given in format &quot;&lt;number&gt; &lt;time unit&gt;&quot;, e.g. 1 day, 30 minutes, 2 weeks, 6 months, 1 year | Optional | 
| title | Ticket Title to filter by | Optional | 
| queue | Ticket Queues to filter by in CSV format (e.g., Raw,Misc) | Optional | 
| priority | Ticket Priority to filter by in CSV format (e.g., 4High,5VeryHigh) | Optional | 
| type | Ticket type to filter by | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OTRS.Ticket.ID | string | Ticket ID | 
| OTRS.Ticket.Created | date | Ticket creation date | 
| OTRS.Ticket.CustomerUser | string | Customer user related to ticket | 
| OTRS.Ticket.Owner | string | Ticket owner | 
| OTRS.Ticket.Priority | string | Ticket priority | 
| OTRS.Ticket.Queue | string | Queue the ticket is in | 
| OTRS.Ticket.State | string | Ticket state | 
| OTRS.Ticket.Title | string | Ticket title | 
| OTRS.Ticket.Type | string | Ticket type | 
| OTRS.Ticket.TicketNumber | string | Ticket number | 


##### Command Example
``` ```

##### Human Readable Output


### otrs-create-ticket
***
Create a new ticket in OTRS


##### Base Command

`otrs-create-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Title to assign to the new ticket | Required | 
| queue | Queue to place the new ticket in | Required | 
| state | State to assign to the new ticket | Required | 
| priority | Priority to assign to the new ticket | Required | 
| customer_user | Customer user related to the new ticket | Required | 
| article_subject | Article Subject to apply to the new ticket | Required | 
| article_body | Text to add to the Article Body of the new ticket | Required | 
| type | Ticket Type to assign to the new ticket | Optional | 
| dynamic_fields | Dynamic fields to apply to the new ticket, in the format: field1=value1,field2=value2. For example: ProcessManagementProcessID=1,ProcessManagementActivityStatus=2 | Optional | 
| attachment | File entry ID of the file to add as an attachment to the new ticket in CSV format, e.g., 123@20,124@21  | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OTRS.Ticket.Article.Subject | string | Ticket article subject | 
| OTRS.Ticket.Article.Body | string | Ticket article body | 
| OTRS.Ticket.ID | string | Ticket ID | 
| OTRS.Ticket.Created | date | Ticket creation date | 
| OTRS.Ticket.Priority | string | Ticket priority | 
| OTRS.Ticket.Queue | string | Queue that the ticket is in | 
| OTRS.Ticket.State | string | Ticket state | 
| OTRS.Ticket.Title | string | Ticket title | 
| OTRS.Ticket.Type | string | Ticket type | 
| OTRS.Ticket.CustomerUser | string | Customer user related to ticket | 
| OTRS.Ticket.DynamicField | string | Ticket dynamic fields | 
| OTRS.Ticket.TicketNumber | string | Ticket number | 


##### Command Example
``` ```

##### Human Readable Output


### otrs-update-ticket
***
Update an OTRS ticket


##### Base Command

`otrs-update-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | Ticket ID of the ticket to update | Required | 
| title | Ticket Title of the ticket to update | Optional | 
| state | Ticket State of the ticket to update | Optional | 
| priority | Priority of the ticket to update | Optional | 
| article_subject | Article Subject of the ticket to update | Optional | 
| article_body | Article Body of the ticket to update | Optional | 
| queue | Queue that the ticket to update is in | Optional | 
| type | Ticket Type of the ticket to update | Optional | 
| dynamic_fields | Dynamic fields to apply to the updated ticket, in the format: field1=value1,field2=value2. For example: ProcessManagementProcessID=1,ProcessManagementActivityStatus=2 | Optional | 
| attachment | File entry ID of the file to add as an attachment to the updated ticket in CSV format, e.g., 123@20,124@21  | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OTRS.Ticket.Article.Subject | string | Ticket article subject | 
| OTRS.Ticket.Article.Body | string | Ticket article body | 
| OTRS.Ticket.ID | string | Ticket ID | 
| OTRS.Ticket.Created | date | Ticket creation date | 
| OTRS.Ticket.Priority | string | Ticket priority | 
| OTRS.Ticket.Queue | string | Queue that the ticket is in | 
| OTRS.Ticket.State | string | Ticket state | 
| OTRS.Ticket.Title | string | Ticket title | 
| OTRS.Ticket.Type | string | Ticket type | 


##### Command Example
``` ```

##### Human Readable Output


### otrs-close-ticket
***
Close an OTRS ticket


##### Base Command

`otrs-close-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | Ticket ID of the ticket to close | Required | 
| article_subject | Article Subject of the ticket to close | Required | 
| article_body | Article Body of the ticket to close | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OTRS.Ticket.ID | string | Ticket ID | 
| OTRS.Ticket.State | string | Ticket state | 
| OTRS.Ticket.Article.Subject | string | Ticket article subject | 
| OTRS.Ticket.Article.Body | string | Ticket article body | 


##### Command Example
``` ```

##### Human Readable Output

