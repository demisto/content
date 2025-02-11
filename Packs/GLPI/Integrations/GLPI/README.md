GLPI open source ITSM solution
This integration was integrated and tested with version 9.5.5 of GLPI

## Configure GLPI in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://example.net/apirest.php) | True |
| Application Token | True |
| User Token | True |
| Fetch incidents | False |
| Incident type | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Incidents Fetch Interval | False |
| Long running instance | False |
| Maximum number of incidents to mirror each time | False |
| Incident Mirror Direction | False |
| Tag used for work note mirroring | False |
| Tag used for comment mirroring | False |
| Tag used for file mirroring | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
| Max incidents fetch at the same time | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### glpi-create-user
***
Create a new GLPI user

Test of mirroring! 1. 2. 3. 4.

#### Base Command

`glpi-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Login. | Required | 
| firstname | Firstname. | Optional | 
| lastname | Lastname. | Optional | 
| email | Email address. | Optional | 
| password | Password. | Required | 
| profile | Profile name. | Optional | 
| additional_fields | Additional fields in the format: fieldname1=value;fieldname2=value;. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.User.id | unknown | Created user ID | 
| GLPI.User.message | unknown | User creation message | 

### glpi-delete-user
***
Delete GLPI user


#### Base Command

`glpi-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Username. | Required | 
| purge | Default : False, will use the trash, use True to definitively remove the user from the system. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

There is no context output for this command.
### glpi-disable-user
***
Disable GLPI user


#### Base Command

`glpi-disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Username. | Required | 


#### Context Output

There is no context output for this command.
### glpi-enable-user
***
Enable GLPI user


#### Base Command

`glpi-enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Username. | Required | 


#### Context Output

There is no context output for this command.
### get-mapping-fields
***
Return the list of fields for an incident type


#### Base Command

`get-mapping-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### get-modified-remote-data
***
Mirroring feature, use only for debug


#### Base Command

`get-modified-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | lastUpdate parameter. Possible values are: . | Optional | 


#### Context Output

There is no context output for this command.
### glpi-get-username
***
Get username by user ID


#### Base Command

`glpi-get-username`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.User | Unknown | GLPI User details | 
| GLPI.User.id | unknown | User id | 
| GLPI.User.username | unknown | Username | 

### glpi-delete-ticket
***
Delete GLPI ticket


#### Base Command

`glpi-delete-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | Ticket ID. | Required | 
| purge | Default : False, will use the trash, use True to definitively remove the ticket from the system. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

There is no context output for this command.
### glpi-get-ticket
***
Get ticket details by ticket ID


#### Base Command

`glpi-get-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The Ticket ID. | Required | 
| get_attachments | If "True" will retrieve ticket attachments. Default is "False". Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.Ticket.actiontime | Unknown | Ticket action time | 
| GLPI.Ticket.begin_waiting_date | Unknown | Ticket begin waiting date | 
| GLPI.Ticket.close_delay_stat | Unknown | Ticket close delay stat | 
| GLPI.Ticket.closedate | Unknown | Tocket closed date | 
| GLPI.Ticket.content | Unknown | Ticket content | 
| GLPI.Ticket.date | Unknown | Ticket date | 
| GLPI.Ticket.date_creation | Unknown | Ticket date creation | 
| GLPI.Ticket.date_mod | Unknown | Ticket date modification | 
| GLPI.Ticket.entities_id | Unknown | Ticket entities ids | 
| GLPI.Ticket.global_validation | Unknown | Ticket global validation | 
| GLPI.Ticket.id | Unknown | Ticket ID | 
| GLPI.Ticket.impact | Unknown | Ticket Impact | 
| GLPI.Ticket.internal_time_to_own | Unknown | Ticket internal time to own | 
| GLPI.Ticket.internal_time_to_resolve | Unknown | Ticket internal time to resolve | 
| GLPI.Ticket.is_deleted | Unknown | Ticket is_deleted? | 
| GLPI.Ticket.itilcategories_id | Unknown | Ticket ITIL categories id | 
| GLPI.Ticket.links | Unknown | Ticket links | 
| GLPI.Ticket.locations_id | Unknown | Tickets locations id | 
| GLPI.Ticket.name | Unknown | Ticket name | 
| GLPI.Ticket.ola_ttr_begin_date | Unknown | Ticket ola ttr begin date | 
| GLPI.Ticket.ola_waiting_duration | Unknown | Ticket ola waiting duration | 
| GLPI.Ticket.olalevels_id_ttr | Unknown | Ticket ola levels id ttr | 
| GLPI.Ticket.olas_id_tto | Unknown | Ticket olas id tto | 
| GLPI.Ticket.olas_id_ttr | Unknown | Ticket olas id ttr | 
| GLPI.Ticket.priority | Unknown | Ticket priority | 
| GLPI.Ticket.requesttypes_id | Unknown | Ticket request types id | 
| GLPI.Ticket.sla_waiting_duration | Unknown | Ticket sla waiting duration | 
| GLPI.Ticket.slalevels_id_ttr | Unknown | Ticket slale levels id ttr | 
| GLPI.Ticket.slas_id_tto | Unknown | Ticket slas id tto | 
| GLPI.Ticket.slas_id_ttr | Unknown | Ticket stats id ttr | 
| GLPI.Ticket.solve_delay_stat | Unknown | Ticket solve delay stat | 
| GLPI.Ticket.solvedate | Unknown | Ticket solve date | 
| GLPI.Ticket.status | Unknown | Ticket status | 
| GLPI.Ticket.takeintoaccount_delay_stat | Unknown | Ticket take into account delay stat | 
| GLPI.Ticket.time_to_own | Unknown | Ticket time to own | 
| GLPI.Ticket.time_to_resolve | Unknown | Ticket time to resolve | 
| GLPI.Ticket.type | Unknown | Ticket type | 
| GLPI.Ticket.urgency | Unknown | Ticket urgency | 
| GLPI.Ticket.users_id_lastupdater | Unknown | Ticket users id last updater | 
| GLPI.Ticket.users_id_recipient | Unknown | Ticket users id recipient | 
| GLPI.Ticket.validation_percent | Unknown | Ticket validation percent | 
| GLPI.Ticket.waiting_duration | Unknown | Ticket waiting duration | 
| File.Info | string | Attachment file info. | 
| File.Name | unknown | Attachment file name. | 
| File.Size | number | Attachment file size. | 
| File.SHA1 | string | Attachment file SHA1 hash. | 
| File.SHA256 | string | Attachment file SHA256 hash. | 
| File.EntryID | string | Attachment file entry ID. | 
| File.Type | string | Attachment file type. | 
| File.MD5 | string | Attachment file MD5 hash. | 

### glpi-create-ticket
***
Create a GLPI ticket


#### Base Command

`glpi-create-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Ticket name. | Required | 
| content | Ticket description. | Required | 
| type | Ticket type. Possible values are: Incident, Request. | Required | 
| status | Ticket status. Possible values are: New, Processing(assigned), Processing(planned), Pending, Solved, Closed. | Optional | 
| urgency | Ticket urgency. Possible values are: Veryhigh, High, Medium, Low, Verylow. | Optional | 
| impact | Ticket impact. Possible values are: Veryhigh, High, Medium, Low, Verylow. | Optional | 
| priority | Ticket priority. Possible values are: Major, Veryhigh, High, Medium, Low, Verylow. | Optional | 
| entryid | File EntryID to upload , multiple files supported. | Optional | 
| entities_id | Ticket entities ID. | Optional | 
| locations_id | Ticket locations ID. | Optional | 
| itilcategories_id | Ticket ITIL categories ID. | Optional | 
| time_to_resolve | Ticket time to resolve, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| time_to_own | Ticket time to own, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| internal_time_to_resolve | Ticket internal time to resolve, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| internal_time_to_own | Ticket internal time to own, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| requesttypes_id | Ticket Request source. Possible values are: Direct, E-Mail, Helpdesk, Other, Phone, Written. | Optional | 
| additional_fields | Additional fields in the format: fieldname1=value;fieldname2=value;. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.Ticket.id | unknown | The created ticket ID | 
| GLPI.Ticket.message | unknown | Result message from ticket creation | 

### glpi-search
***
Search GLPI items


#### Base Command

`glpi-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_type | Item type to search (ex : Ticket). | Required | 
| query | The search query, please visit https://github.com/glpi-project/glpi/blob/master/apirest.md#search-items. | Optional | 
| forcedisplay | Coma separated additional fields to display. | Optional | 
| srange | Search range limit (ex : 0-50). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.Search | unknown | Search results | 
| GLPI.Search.item_type | unknown | This varies depending on the input item_type \(case sensitive\) | 

### glpi-add-comment
***
Add comment to ticket ID


#### Base Command

`glpi-add-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket ID. | Required | 
| comment | ticket comment. Possible values are: . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.Comment.id | unknown | Created comment ID  | 
| GLPI.Comment.message | unknown | GLPI message | 

### glpi-upload-file
***
Upload document


#### Base Command

`glpi-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryid | File EntryID. Possible values are: . | Required | 
| filename | Filename. Possible values are: . | Optional | 
| doc_name | Doc name. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.Document | Unknown | Document | 
| GLPI.Document.id | unknown | Created document ID | 
| GLPI.Document.message | unknown | GLPI upload message | 
| GLPI.Document.upload_result.filename.size | unknown | Uploaded file size | 
| GLPI.Document.upload_result.filename.display | unknown | File display name | 
| GLPI.Document.upload_result.filename.deleteUrl | Unknown | Document deleteURL | 
| GLPI.Document.upload_result.filename.deleteType | Unknown | Document deleteType | 
| GLPI.Document.upload_result.filename.name | unknown | system file name | 
| GLPI.Document.upload_result.filename.url | unknown | Document URL | 
| GLPI.Document.upload_result.filename.id | Unknown | Document filename id | 

### glpi-get-item
***
Get item details by item type and item ID


#### Base Command

`glpi-get-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_type | Item type. Possible values are: . | Required | 
| item_id | Item ID. Possible values are: . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.item_type | unknown | This varies depending on the input item_type \(case sensitive\) | 

### glpi-update-ticket
***
Update a GLPI ticket


#### Base Command

`glpi-update-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ticket id. | Required | 
| description | Ticket description. | Optional | 
| type | Ticket type. Possible values are: Incident, Request. | Optional | 
| status | Ticket status. Possible values are: New, Processing(assigned), Processing(planned), Pending, Solved, Closed. | Optional | 
| urgency | Ticket urgency. Possible values are: Veryhigh, High, Medium, Low, Verylow. | Optional | 
| impact | Ticket impact. Possible values are: Veryhigh, High, Medium, Low, Verylow. | Optional | 
| priority | Ticket priority. Possible values are: Major, Veryhigh, High, Medium, Low, Verylow. | Optional | 
| entryid | File EntryID to upload , multiple files supported. | Optional | 
| entities_id | Ticket entities ID. | Optional | 
| locations_id | Ticket locations ID. | Optional | 
| itilcategories_id | Ticket ITIL categories ID. | Optional | 
| global_validation | Global validation. Possible values are: . | Optional | 
| time_to_resolve | Ticket time to resolve, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| time_to_own | Ticket time to own, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| internal_time_to_resolve | Ticket internal time to resolve, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| internal_time_to_own | Ticket internal time to own, in the format: YYYY-MM-DD HH:MM:SS. | Optional | 
| additional_fields | Additional fields in the format: fieldname1=value;fieldname2=value;. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.Ticket.id | unknown | The updated ticket ID | 
| GLPI.Ticket.message | unknown | Result message from ticket update | 

### get-remote-data
***
get remote data command


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ticket id. Possible values are: . | Optional | 
| lastUpdate | last update parameter. Possible values are: . | Optional | 


#### Context Output

There is no context output for this command.
### glpi-add-link
***
Link tickets


#### Base Command

`glpi-add-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_ID_1 | First ticket ID. | Required | 
| ticket_ID_2 | Second ticket ID. | Required | 
| link | Relation between tickets. Possible values are: Link, Duplicate, Child, Parent. | Required | 


#### Context Output

There is no context output for this command.
### glpi-update-user
***
Update a user


#### Base Command

`glpi-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### glpi-get-userid
***
Get GLPI User ID by Username


#### Base Command

`glpi-get-userid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Username. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLPI.User | Unknown | GLPI User details | 
| GLPI.User.id | unknown | User id | 
| GLPI.User.username | unknown | Username | 