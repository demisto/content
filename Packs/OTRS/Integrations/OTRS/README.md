Service management suite that comprises ticketing, workflow automation, and notification.
This integration was integrated and tested with OTRS versions 5, 6, and 7.

## Prerequisite

Before configuring OTRS on Cortex XSOAR, you need to enable the webservices in your OTRS instance. It is recommended to use the provided [YAML webservice configuration template](https://gitlab.com/rhab/PyOTRS/raw/master/webservices_templates/GenericTicketConnectorREST.yml), which includes the Route: /TicketList endpoint required for PyOTRS but which is not included in the default OTRS webservice setup. If you use a different file than the template, make sure to name your file `GenericTicketConnectorREST.yml`.

## Configure OTRS on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OTRS.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | OTRS Server URL \(for example http://example.com \)| True |
| credentials | OTRS Credentials | True |
| unsecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| fetch_queue | Queues to fetch tickets from  \(&quot;Any&quot; fetches from all queues. CSV supported, for example Misc, Raw\) | False |
| fetch_priority | Fetch tickets in priority | False |
| fetch_time | First fetch timestamp \(formatted as &lt;number&gt; &lt;time unit&gt;, for example 12 hours, 7 days, 3 months, 1 year\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### otrs-get-ticket
***
Retrieves details for an OTRS ticket by ticket ID or ticket number. At least one input argument is required for the integration to run.


##### Base Command

`otrs-get-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | Ticket ID of the ticket to get details for. If not spcecified, the ticket_number argument is required. | Optional | 
| ticket_number | Ticket Number of the ticket to get details for. If not specified, the ticket_id argument is required. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OTRS.Ticket.ID | string | Ticket ID | 
| OTRS.Ticket.Number | string | Ticket number | 
| OTRS.Ticket.Created | date | Ticket creation date | 
| OTRS.Ticket.CustomerUser | string | Customer user related to the ticket | 
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


##### Command Example
```!otrs-get-ticket ticket_id="7023"```

##### Context Example
```
{
    "OTRS": {
        "Ticket": {
            "Age": "0 h 09 m",
            "Article": [
                {
                    "Body": "Testing",
                    "ContentType": "text/plain; charset=utf8",
                    "CreateTime": "2020-04-26 11:05:07",
                    "From": "\"Jens Bothe\" <jens.bothe@otrs.com\>",
                    "ID": "11187",
                    "Subject": "TestArticle"
                },
                {
                    "Body": "ClosingBody",
                    "ContentType": "text/plain; charset=utf8",
                    "CreateTime": "2020-04-26 11:05:12",
                    "From": "SIEM Webservice",
                    "ID": "11188",
                    "Subject": "ClosingSubject"
                }
            ],
            "Created": "2020-04-26 11:05:07",
            "CustomerID": "jb",
            "DynamicField": {
                "Firstname": "Jens",
                "Gender": "male"
            },
            "ID": "7023",
            "Lock": "unlock",
            "Number": "2020042610000031",
            "Owner": "siem",
            "Priority": "1 very low",
            "Queue": "Inbox::SIEM",
            "State": "open",
            "Title": "UpdatedTitle",
            "Type": "Incident"
        }
    }
}
```

##### Human Readable Output
### OTRS Ticket 7023
|ID|Number|Age|Title|State|Lock|Queue|Owner|CustomerID|Priority|Type|Created|DynamicField|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 7023 | 2020042610000031 | 0 h 09 m | UpdatedTitle | open | unlock | Inbox::SIEM | siem | jb | 1 very low | Incident | 2020-04-26 11:05:07 | Firstname: Jens<br />Gender: male |
### Articles
|ID|From|Subject|Body|CreateTime|ContentType|
|---|---|---|---|---|---|
| 11187 | "Jens Bothe" <jens.bothe@otrs.com\> | TestArticle | Testing | 2020-04-26 11:05:07 | text/plain; charset=utf8 |
| 11188 | SIEM Webservice | ClosingSubject | ClosingBody | 2020-04-26 11:05:12 | text/plain; charset=utf8 |


### otrs-search-ticket
***
Search for an OTRS ticket using search filters


##### Base Command

`otrs-search-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Ticket states to filter for in CSV format (for example New, Open) | Optional | 
| created_before | Filter for a ticket created before this date. (formatted as &lt;number&gt; &lt;time unit&gt;, for example 1 day, 30 minutes, 2 weeks, 6 months, 1 year) | Optional | 
| created_after | Filter for a ticket created after this date. (formatted as &lt;number&gt; &lt;time unit&gt;, for example 1 day, 30 minutes, 2 weeks, 6 months, 1 year) | Optional | 
| title | Ticket Title to filter for | Optional | 
| queue | Ticket Queues to filter for in CSV format (for example Raw,Misc) | Optional | 
| priority | Ticket priority to filter for in CSV format (for example 4High,5VeryHigh) | Optional | 
| type | Ticket type to filter for | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OTRS.Ticket.ID | string | Ticket ID | 
| OTRS.Ticket.Number | string | Ticket number | 
| OTRS.Ticket.Created | date | Ticket creation date | 
| OTRS.Ticket.CustomerUser | string | Customer user related to ticket | 
| OTRS.Ticket.Owner | string | Ticket owner | 
| OTRS.Ticket.Priority | string | Ticket priority | 
| OTRS.Ticket.Queue | string | Queue the ticket is in | 
| OTRS.Ticket.State | string | Ticket state | 
| OTRS.Ticket.Title | string | Ticket title | 
| OTRS.Ticket.Type | string | Ticket type | 


##### Command Example
```!otrs-search-ticket state="PendingReminder" title="7023"```

##### Context Example
```
{}
```

##### Human Readable Output
No results found

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
| article_subject | Article subject to apply to the new ticket | Required | 
| article_body | Text to add to the article body of the new ticket | Required | 
| type | Ticket type to assign to the new ticket | Optional | 
| dynamic_fields | Dynamic fields to apply to the new ticket in the format: field1=value1,field2=value2. For example: ProcessManagementProcessID=1,ProcessManagementActivityStatus=2 | Optional | 
| attachment | File entry ID of the file to add as an attachment to the new ticket in CSV format. For example: 123@20,124@21  | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OTRS.Ticket.Article.Subject | string | Ticket article subject | 
| OTRS.Ticket.Article.Body | string | Ticket article body | 
| OTRS.Ticket.ID | string | Ticket ID | 
| OTRS.Ticket.Number | string | Ticket number | 
| OTRS.Ticket.Created | date | Ticket creation date | 
| OTRS.Ticket.Priority | string | Ticket priority | 
| OTRS.Ticket.Queue | string | Queue that the ticket is in | 
| OTRS.Ticket.State | string | Ticket state | 
| OTRS.Ticket.Title | string | Ticket title | 
| OTRS.Ticket.Type | string | Ticket type | 
| OTRS.Ticket.CustomerUser | string | Customer user related to ticket | 
| OTRS.Ticket.DynamicField | string | Ticket dynamic fields | 


##### Command Example
```!otrs-create-ticket title="TestTicket" queue="Inbox::SIEM" state="New" priority="2Low" customer_user="jb" article_subject="TestArticle" article_body="Testing" type="Unclassified"```

##### Context Example
```
{
    "OTRS": {
        "Ticket": {
            "Article": {
                "Body": "Testing",
                "Subject": "TestArticle"
            },
            "CustomerUser": "jb",
            "DynamicField": [],
            "ID": "7024",
            "Number": "2020042610000049",
            "Priority": "2 low",
            "Queue": "Inbox::SIEM",
            "State": "new",
            "Title": "TestTicket",
            "Type": "Unclassified"
        }
    }
}
```

##### Human Readable Output
Created ticket 7024 successfully

### otrs-update-ticket
***
Update an OTRS ticket


##### Base Command

`otrs-update-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | Ticket ID of the ticket to update | Required | 
| title | Ticket title of the ticket to update | Optional | 
| state | Ticket state of the ticket to update | Optional | 
| priority | Priority of the ticket to update | Optional | 
| article_subject | Article subject of the ticket to update | Optional | 
| article_body | Article body of the ticket to update | Optional | 
| queue | Queue that the ticket to update is in | Optional | 
| type | Ticket type of the ticket to update | Optional | 
| dynamic_fields | Dynamic fields to apply to the updated ticket, in the format: field1=value1,field2=value2. For example: ProcessManagementProcessID=1,ProcessManagementActivityStatus=2 | Optional | 
| attachment | File entry ID of the file to add as an attachment to the updated ticket in CSV format. For example: 123@20,124@21  | Optional | 


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
```!otrs-update-ticket ticket_id="7023" title="UpdatedTitle" state="Open" priority="1VeryLow" type="Incident"```

##### Context Example
```
{
    "OTRS": {
        "Ticket": {
            "ID": "7023",
            "Priority": "1 very low",
            "State": "open",
            "Title": "UpdatedTitle",
            "Type": "Incident"
        }
    }
}
```

##### Human Readable Output
Updated ticket 7023 successfully

### otrs-close-ticket
***
Close an OTRS ticket


##### Base Command

`otrs-close-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | Ticket ID of the ticket to close | Required | 
| article_subject | Article subject of the ticket to close | Required | 
| article_body | Article body of the ticket to close | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OTRS.Ticket.ID | string | Ticket ID | 
| OTRS.Ticket.State | string | Ticket state | 
| OTRS.Ticket.Article.Subject | string | Ticket article subject | 
| OTRS.Ticket.Article.Body | string | Ticket article body | 


##### Command Example
```!otrs-close-ticket ticket_id="7023" article_subject="ClosingSubject" article_body="ClosingBody"```

##### Context Example
```
{
    "OTRS": {
        "Ticket": {
            "Article": {
                "Body": "ClosingBody",
                "Subject": "ClosingSubject"
            },
            "ID": "7023",
            "State": "closed successful"
        }
    }
}
```

##### Human Readable Output
Closed ticket 7023 successfully
