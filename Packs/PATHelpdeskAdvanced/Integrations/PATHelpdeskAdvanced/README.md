Improve the effectiveness of your service provision and resources, and the quality of your IT department.
This integration was integrated and tested with version xx of PATHelpdeskAdvanced.

## Configure PAT HelpdeskAdvanced on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PAT HelpdeskAdvanced.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | PAT Helpdesk URL | True |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### hda-create-ticket

***
Create a new ticket.

#### Base Command

`hda-create-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type_id | The object type ID for the ticket. | Required | 
| ticket_status_id | The status ID for the ticket. Use hda-list-ticket-statuses to get a list of status IDs. | Required | 
| ticket_priority_id | The priority ID for the ticket. Use hda-list-ticket-priorities to get a list of priority IDs. | Required | 
| object_description | The description of the object. | Optional | 
| ticket_classification_id | The classification ID for the ticket. | Optional | 
| ticket_type_id | The type ID for the ticket. | Optional | 
| contact_id | The contact ID for the ticket. | Optional | 
| subject | The subject for the ticket. | Optional | 
| problem | The problem description for the ticket. | Optional | 
| site | The site for the ticket. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelpdeskAdvanced.Ticket.AccountID | string | The account ID of the ticket. | 
| HelpdeskAdvanced.Ticket.AssetCategoryID | string | The asset category ID of the ticket. | 
| HelpdeskAdvanced.Ticket.AssetID | string | The asset ID of the ticket. | 
| HelpdeskAdvanced.Ticket.AssignedUserGroupID | string | The assigned user group ID of the ticket. | 
| HelpdeskAdvanced.Ticket.AssignedUserID | string | The assigned user ID of the ticket. | 
| HelpdeskAdvanced.Ticket.AssignedUserOrGroupID | string | The assigned user or group ID of the ticket. | 
| HelpdeskAdvanced.Ticket.BilledTokens | string | The billed tokens of the ticket. | 
| HelpdeskAdvanced.Ticket.BusinessFunctionID | string | The business function ID of the ticket. | 
| HelpdeskAdvanced.Ticket.C12 | string | The C12 field of the ticket. | 
| HelpdeskAdvanced.Ticket.C13 | string | The C13 field of the ticket. | 
| HelpdeskAdvanced.Ticket.C134C | string | The C134C field of the ticket. | 
| HelpdeskAdvanced.Ticket.C14 | string | The C14 field of the ticket. | 
| HelpdeskAdvanced.Ticket.C15 | string | The C15 field of the ticket. | 
| HelpdeskAdvanced.Ticket.CalendarID | string | The calendar ID of the ticket. | 
| HelpdeskAdvanced.Ticket.ClosedByUserID | string | The ID of the user who closed the ticket. | 
| HelpdeskAdvanced.Ticket.ClosureDate | string | The closure date of the ticket. | 
| HelpdeskAdvanced.Ticket.ContactID | string | The contact ID of the ticket. | 
| HelpdeskAdvanced.Ticket.CostCenterID | string | The cost center ID of the ticket. | 
| HelpdeskAdvanced.Ticket.CustomerContractID | string | The customer contract ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Date | date | The date of the ticket. | 
| HelpdeskAdvanced.Ticket.DefaultSolutionID | string | The default solution ID of the ticket. | 
| HelpdeskAdvanced.Ticket.EstimatedTaskDuration | string | The estimated task duration of the ticket. | 
| HelpdeskAdvanced.Ticket.EstimatedTaskStartDate | string | The estimated task start date of the ticket. | 
| HelpdeskAdvanced.Ticket.ExpirationDate | date | The expiration date of the ticket. | 
| HelpdeskAdvanced.Ticket.FirstUpdateUserID | string | The ID of the user who first updated the ticket. | 
| HelpdeskAdvanced.Ticket.FullText | string | The full text of the ticket. | 
| HelpdeskAdvanced.Ticket.ID | string | The ID of the ticket. | 
| HelpdeskAdvanced.Ticket.ImpactID | string | The impact ID of the ticket. | 
| HelpdeskAdvanced.Ticket.IsNew | boolean | Whether the ticket is new or not. | 
| HelpdeskAdvanced.Ticket.KnownIssue | string | The known issue field of the ticket. | 
| HelpdeskAdvanced.Ticket.LanguageID | string | The language ID of the ticket. | 
| HelpdeskAdvanced.Ticket.LastExpirationDate | date | The last expiration date of the ticket. | 
| HelpdeskAdvanced.Ticket.LastExpirationID | string | The last expiration ID of the ticket. | 
| HelpdeskAdvanced.Ticket.LocationID | string | The location ID of the ticket. | 
| HelpdeskAdvanced.Ticket.MailBoxID | string | The mailbox ID of the ticket. | 
| HelpdeskAdvanced.Ticket.NextExpirationDate | string | The next expiration date of the ticket. | 
| HelpdeskAdvanced.Ticket.NextExpirationID | string | The next expiration ID of the ticket. | 
| HelpdeskAdvanced.Ticket.ObjectDescription | string | The object description of the ticket. | 
| HelpdeskAdvanced.Ticket.ObjectEntity | string | The object entity of the ticket. | 
| HelpdeskAdvanced.Ticket.ObjectTypeID | string | The object type ID of the ticket. | 
| HelpdeskAdvanced.Ticket.OwnerUserGroupID | string | The owner user group ID of the ticket. | 
| HelpdeskAdvanced.Ticket.OwnerUserID | string | The owner user ID of the ticket. | 
| HelpdeskAdvanced.Ticket.ParentRecurringTicketID | string | The parent recurring ticket ID of the ticket. | 
| HelpdeskAdvanced.Ticket.ParentTicketID | string | The parent ticket ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Problem | string | The problem field of the ticket. | 
| HelpdeskAdvanced.Ticket.ProblemHTML | string | The problem field in HTML format of the ticket. | 
| HelpdeskAdvanced.Ticket.RemoteID | string | The remote ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Score | string | The score of the ticket. | 
| HelpdeskAdvanced.Ticket.ServiceID | string | The service ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Site | string | The site of the ticket. | 
| HelpdeskAdvanced.Ticket.SiteUnRead | string | Whether the ticket is unread for the site. | 
| HelpdeskAdvanced.Ticket.Solicits | string | Whether the ticket solicits feedback. | 
| HelpdeskAdvanced.Ticket.SolutionHTML | string | The solution in HTML format of the ticket. | 
| HelpdeskAdvanced.Ticket.SourceMailBoxID | string | The source mailbox ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Subject | string | The subject of the ticket. | 
| HelpdeskAdvanced.Ticket.SupplierID | string | The supplier ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Tag | string | The tag of the ticket. | 
| HelpdeskAdvanced.Ticket.TaskEffort | string | The task effort of the ticket. | 
| HelpdeskAdvanced.Ticket.TemplateTicketID | string | The template ticket ID of the ticket. | 
| HelpdeskAdvanced.Ticket.TicketClassificationID | string | The ticket classification ID of the ticket. | 
| HelpdeskAdvanced.Ticket.TicketCode | string | The ticket code of the ticket. | 
| HelpdeskAdvanced.Ticket.TicketPriorityID | string | The ticket priority ID of the ticket. | 
| HelpdeskAdvanced.Ticket.TicketSolutionID | string | The ticket solution ID of the ticket. | 
| HelpdeskAdvanced.Ticket.TicketSourceID | string | The ticket source ID of the ticket. | 
| HelpdeskAdvanced.Ticket.TicketStatusID | string | The ticket status ID of the ticket. | 
| HelpdeskAdvanced.Ticket.TicketTypeID | string | The ticket type ID of the ticket. | 
| HelpdeskAdvanced.Ticket.UnRead | string | Whether the ticket is unread. | 
| HelpdeskAdvanced.Ticket.UrgencyID | string | The urgency ID of the ticket. | 
| HelpdeskAdvanced.Ticket.UserID | string | The user ID of the ticket. | 

### hda-list-tickets

***
List tickets.

#### Base Command

`hda-list-tickets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ID of the ticket to retrieve. | Optional | 
| filter | Filters to apply to the ticket list. | Optional | 
| page | The page number to retrieve. | Optional | 
| page_size | The number of tickets per page. | Optional | 
| limit | The maximum number of tickets to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelpdeskAdvanced.Ticket.AccountID | string | The account ID of the ticket. | 
| HelpdeskAdvanced.Ticket.AssetID | string | The asset ID of the ticket. | 
| HelpdeskAdvanced.Ticket.BilledTokens | string | The billed tokens of the ticket. | 
| HelpdeskAdvanced.Ticket.CalendarID | string | The calendar ID of the ticket. | 
| HelpdeskAdvanced.Ticket.ClosureDate | string | The closure date of the ticket. | 
| HelpdeskAdvanced.Ticket.ContactID | string | The contact ID of the ticket. | 
| HelpdeskAdvanced.Ticket.CustomerContractID | string | The customer contract ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Date | string | The date of the ticket. | 
| HelpdeskAdvanced.Ticket.EstimatedTaskDuration | string | The estimated task duration of the ticket. | 
| HelpdeskAdvanced.Ticket.EstimatedTaskStartDate | string | The estimated task start date of the ticket. | 
| HelpdeskAdvanced.Ticket.ExpirationDate | string | The expiration date of the ticket. | 
| HelpdeskAdvanced.Ticket.FirstUpdateUserID | string | The ID of the user who first updated the ticket. | 
| HelpdeskAdvanced.Ticket.ID | string | The ID of the ticket. | 
| HelpdeskAdvanced.Ticket.KnownIssue | string | The known issue field of the ticket. | 
| HelpdeskAdvanced.Ticket.LanguageID | string | The language ID of the ticket. | 
| HelpdeskAdvanced.Ticket.LastExpirationDate | string | The last expiration date of the ticket. | 
| HelpdeskAdvanced.Ticket.LocationID | string | The location ID of the ticket. | 
| HelpdeskAdvanced.Ticket.MailBoxID | string | The mailbox ID of the ticket. | 
| HelpdeskAdvanced.Ticket.NextExpirationDate | string | The next expiration date of the ticket. | 
| HelpdeskAdvanced.Ticket.NextExpirationID | string | The next expiration ID of the ticket. | 
| HelpdeskAdvanced.Ticket.OwnerUserID | string | The owner user ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Problem | string | The problem field of the ticket. | 
| HelpdeskAdvanced.Ticket.ProblemHTML | string | The problem field in HTML format of the ticket. | 
| HelpdeskAdvanced.Ticket.Score | string | The score of the ticket. | 
| HelpdeskAdvanced.Ticket.ServiceID | string | The service ID of the ticket. | 
| HelpdeskAdvanced.Ticket.SiteUnRead | string | Whether the ticket is unread for the site. | 
| HelpdeskAdvanced.Ticket.Solicits | string | Whether the ticket solicits feedback. | 
| HelpdeskAdvanced.Ticket.Solution | string | The solution of the ticket. | 
| HelpdeskAdvanced.Ticket.SolutionHTML | string | The solution in HTML format of the ticket. | 
| HelpdeskAdvanced.Ticket.Subject | string | The subject of the ticket. | 
| HelpdeskAdvanced.Ticket.SupplierID | string | The supplier ID of the ticket. | 
| HelpdeskAdvanced.Ticket.TaskEffort | string | The task effort of the ticket. | 
| HelpdeskAdvanced.Ticket.TicketClassificationID | string | The ticket classification ID of the ticket. | 
| HelpdeskAdvanced.Ticket.TicketTypeID | string | The ticket type ID of the ticket. | 
| HelpdeskAdvanced.Ticket.UrgencyID | string | The urgency ID of the ticket. | 

### hda-add-ticket-attachment

***
Add an attachment to a ticket.

#### Base Command

`hda-add-ticket-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket ID to retrieve details for. | Required | 
| entry_id | The file entry ID to attach. | Required | 

#### Context Output

There is no context output for this command.
### hda-list-ticket-attachments

***
List attachments for a ticket.

#### Base Command

`hda-list-ticket-attachments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket ID to retrieve details for. | Required | 
| limit | The maximum number of tickets to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelpdeskAdvanced.Ticket.Attachment.BlobID | string | The blob ID of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.ContentType | string | The content type of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.Description | string | The description of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.EmailID | string | The email ID of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.FileName | string | The file name of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.FirstUpdate | string | The date and time when the attachment was first updated. | 
| HelpdeskAdvanced.Ticket.Attachment.FirstUpdateUserID | string | The ID of the user who first uploaded the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.ID | string | The ID of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.IsNew | string | Indicates whether the attachment is new. | 
| HelpdeskAdvanced.Ticket.Attachment.KBSize | string | The size of the attachment in KB. | 
| HelpdeskAdvanced.Ticket.Attachment.LastUpdate | string | The date and time when the attachment was last updated. | 
| HelpdeskAdvanced.Ticket.Attachment.LastUpdateUserID | string | The ID of the user who last updated the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.Note | string | Any additional notes about the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.ObjectDescription | string | The description of the object the attachment is associated with. | 
| HelpdeskAdvanced.Ticket.Attachment.ObjectEntity | string | The object entity of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.ObjectTypeID | string | The object type ID of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.OwnerUserID | string | The owner user ID of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.ParentObject | string | The parent object the attachment is associated with. | 
| HelpdeskAdvanced.Ticket.Attachment.ParentObjectID | string | The ID of the parent object the attachment is associated with. | 
| HelpdeskAdvanced.Ticket.Attachment.RemoteID | string | The remote ID of the attachment. | 
| HelpdeskAdvanced.Ticket.Attachment.Site | string | The site ID the attachment is associated with. | 
| HelpdeskAdvanced.Ticket.Attachment.TicketID | string | The ticket ID the attachment is associated with. | 
| HelpdeskAdvanced.Ticket.Attachment.UniqueID | string | A unique ID for the attachment. | 

### hda-add-ticket-comment

***
Add a comment to a ticket.

#### Base Command

`hda-add-ticket-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket ID to retrieve details for. | Required | 
| comment | The comment text. | Required | 
| site_visible | Whether the ticket is visible to the customer site. Possible values are: True, False. Default is False. | Required | 

#### Context Output

There is no context output for this command.
### hda-list-ticket-statuses

***
List ticket statuses.

#### Base Command

`hda-list-ticket-statuses`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of statuses to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelpdeskAdvanced.TicketStatus.ID | Number | The status ID. | 
| HelpdeskAdvanced.TicketStatus.Name | String | The status name. | 

### hda-change-ticket-status

***
Change the status of a ticket.

#### Base Command

`hda-change-ticket-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ID of the ticket to change status for. | Required | 
| status_id | The ID of the status to change the ticket to. | Required | 
| note | An optional note to add with the status change. | Optional | 

#### Context Output

There is no context output for this command.
### hda-list-ticket-priorities

***
List ticket priorities.

#### Base Command

`hda-list-ticket-priorities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ID of the ticket to change status for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelpdeskAdvanced.TicketPriority.ID | Number | The priority ID. | 
| HelpdeskAdvanced.TicketPriority.Name | String | The priority name. | 

### hda-get-ticket-history

***
Get ticket history.

#### Base Command

`hda-get-ticket-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ID of the ticket to change status for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelpdeskAdvanced.Ticket.AccountID | string | The account ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Attachments | string | List of attachments for the ticket. | 
| HelpdeskAdvanced.Ticket.AutEmailCounter | string | The aut email counter. | 
| HelpdeskAdvanced.Ticket.ContactID | string | The contact ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Data.Comment | string | The comment text. | 
| HelpdeskAdvanced.Ticket.Data.Date | string | The date of the history entry. | 
| HelpdeskAdvanced.Ticket.Data.From | string | The user who made the change. | 
| HelpdeskAdvanced.Ticket.Data.FromID | string | The ID of the user who made the change. | 
| HelpdeskAdvanced.Ticket.Data.Problem | string | The problem associated with the history entry. | 
| HelpdeskAdvanced.Ticket.Data.To | string | The user/team the ticket was assigned to. | 
| HelpdeskAdvanced.Ticket.Data.ToID | string | The ID of the user/team the ticket was assigned to. | 
| HelpdeskAdvanced.Ticket.ExternalAction | string | The external action associated with the history entry. | 
| HelpdeskAdvanced.Ticket.FullName | string | The full name of the ticket. | 
| HelpdeskAdvanced.Ticket.HistoryID | string | The ID of the history entry. | 
| HelpdeskAdvanced.Ticket.OperationDescription | string | The description of the operation. | 
| HelpdeskAdvanced.Ticket.OperationTypeID | string | The type ID of the operation. | 
| HelpdeskAdvanced.Ticket.UpdateDate | date | The date the ticket was last updated. | 
| HelpdeskAdvanced.Ticket.UserID | string | The user ID of the ticket. | 
| HelpdeskAdvanced.Ticket.Username | string | The username associated with the ticket. | 

### hda-list-users

***
List users.

#### Base Command

`hda-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user to retrieve details for. | Optional | 
| page | The page number. | Optional | 
| page_size | The number of users to return per page. | Optional | 
| limit | The maximum number of users to return per page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelpdeskAdvanced.User.ID | string | The user ID. | 
| HelpdeskAdvanced.User.Email | string | The user's email address. | 
| HelpdeskAdvanced.User.FirstName | string | The user's first name. | 
| HelpdeskAdvanced.User.LastName | string | The user's last name. | 
| HelpdeskAdvanced.User.Phone | string | The user's phone number. | 

### hda-list-groups

***
List groups.

#### Base Command

`hda-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to retrieve details for. | Optional | 
| page | The page number. | Optional | 
| page_size | The number of groups to return per page. | Optional | 
| limit | The maximum number of groups to return per page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelpdeskAdvanced.Group.ID | string | The group ID. | 
| HelpdeskAdvanced.Group.ObjectTypeID | string | The object type ID of the group. | 
| HelpdeskAdvanced.Group.Description | string | The group description. | 
