Microsoft Graph lets your app get authorized access to a user's Outlook mail data in a personal or organization account.
This integration was integrated and tested with version v1 of Microsoft Graph.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure O365 Outlook Mail (Using Graph API) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Application ID or Client ID | See the Help tab. | False |
| Token or Tenant ID | See the Help tab. | False |
| Key or Client Secret | See the Help tab. | False |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp; secrets" page of the app. | False |
| Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
| Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
| Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
| Fetch incidents | Whether to fetch incidents. | False |
| Email address from which to fetch incidents | For example, "example@demisto.com" | False |
| Name of the folder or sub-folder from which to fetch incidents | Supports folder ID and sub-folders, for example Inbox/Phishing. | False |
| First fetch timestamp | \<number\> /<time unit\>, for example 12 hours, 7 days. | False |
| HTTP Timeout | The timeout of the HTTP requests sent to Microsoft Graph API \(in seconds\). | False |
| Maximum number of emails to pull per fetch |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Use a self deployed Azure application |  | False |
| Incident type |  | False |
| ID or Client ID - see Detailed Instructions (?) |  | False |
| Token or Tenant ID - see Detailed Instructions (?) |  | False |
| Key or Client Secret (Deprecated) |  | False |
| ID or Client ID - see Detailed Instructions (?) (Deprecated) |  | False |
| Token or Tenant ID - see Detailed Instructions (?) (Deprecated) |  | False |
| Display full email body | If not active, only a preview of the email will be fetched. |  |
| Mark fetched emails as read | Relevant only if fetch incidents is active. |  |
| Advanced: Time in minutes to look back when fetching emails | Use this parameter to determine how far backward to look in the search for incidents that were created before the last run time and did not match the query when they were created. | False |


### Required Permissions

The following permissions are required for all commands:

- Mail.ReadWrite - Application
- Mail.Send - Application
- MailboxSettings.ReadWrite - Application

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-mail-list-emails

***
Gets the properties of returned emails. Typically shows partial results, use the "page_size" and "pages_to_pull" arguments to get all results.


#### Base Command

`msgraph-mail-list-emails`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID from which to pull mails (can be principal ID (email address)). | Required | 
| folder_id |  A comma-separated list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box). . | Optional | 
| odata | An OData query. See REDAME for OData usage examples. | Optional | 
| search | The term for which to search. This argument cannot contain reserved characters such as !, $, #, @, etc. For further information, see <https://tools.ietf.org/html/rfc3986#section-2.2>. | Optional | 
| page_size | Limit emails to fetch in one request. Default is 20. | Optional | 
| pages_to_pull | The number of pages of emails to return (maximum is 10 emails per page). Default is 1. | Optional | 
| ran_once_flag | flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.ID | String | The ID of the email. | 
| MSGraphMail.Created | Date | The time the email was created. | 
| MSGraphMail.LastModifiedTime | Date | The time the email was last modified. | 
| MSGraphMail.ReceivedTime | Date | The time the email was received. | 
| MSGraphMail.SendTime | Date | The time the email was sent. | 
| MSGraphMail.Categories | String | Categories of the email. | 
| MSGraphMail.HasAttachments | Boolean | Whether the email has attachments. | 
| MSGraphMail.Subject | String | The subject of email. | 
| MSGraphMail.IsDraft | Boolean | Whether the email is a draft. | 
| MSGraphMail.Body | String | The content \(body\) of the email. | 
| MSGraphMail.Sender.Name | String | The name of sender. | 
| MSGraphMail.Sender.Address | String | The email address of the sender. | 
| MSGraphMail.From.Name | String | The name of the user in the 'from' field of the email. | 
| MSGraphMail.From.Address | String | The email address of the user in the 'from' field of the email. | 
| MSGraphMail.CCRecipients.Name | String | The names of the CC recipients. | 
| MSGraphMail.CCRecipients.Address | String | The email address of the user in the 'cc' field of the email. | 
| MSGraphMail.BCCRecipients.Name | String | The names of the users in the 'bcc' field of the email. | 
| MSGraphMail.BCCRecipients.Address | String | The email address of the user in the 'bcc' field of the email. | 
| MSGraphMail.ReplyTo.Name | String | The name in the 'replyTo' field of the email. | 
| MSGraphMail.ReplyTo.Address | String | The email address in the 'replyTo' field of the email. | 
| MSGraphMail.UserID | String | The ID of the user. | 
| MSGraphMail.ConversationID | String | The ID of the conversation. | 
| MSGraphMail.InternetMessageID | String | Internet Message ID of the message. | 
| MSGraphMail.Recipients.Name | String | The name of the user in the 'toRecipients' field of the email. | 
| MSGraphMail.Recipients.Address | String | The email address of the user in the 'toRecipients' field of the email. | 
| MSGraphMail.NextPage | String | A token to pass to the next list command to retrieve additional results. | 

### msgraph-mail-get-email

***
Returns the properties of an email.


#### Base Command

`msgraph-mail-get-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| message_id | The unique ID of the mail. You cannot use the the 'MessageID' key in the form '&lt;message-id&gt;'. | Required | 
| folder_id | The folder ID. | Optional | 
| odata | An OData query. See the README for OData usage examples. | Optional | 
| get_body | Whether to return the message body. Possible values are: true, false. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.ID | String | The ID of the email. | 
| MSGraphMail.Created | Date | The time the email was created. | 
| MSGraphMail.LastModifiedTime | Date | The time the email was last modified. | 
| MSGraphMail.ReceivedTime | Date | The time the email was received. | 
| MSGraphMail.SendTime | Date | The time the email was sent. | 
| MSGraphMail.Categories | String | Categories of the email. | 
| MSGraphMail.HasAttachments | Boolean | Whether the email has attachments. | 
| MSGraphMail.Subject | String | The subject of email. | 
| MSGraphMail.IsDraft | Boolean | Whether the email is a draft. | 
| MSGraphMail.Body | String | The content \(body\) of the email. | 
| MSGraphMail.Sender.Name | String | The name of sender. | 
| MSGraphMail.Sender.Address | String | The email address of the sender. | 
| MSGraphMail.From.Name | String | The name of the user in the 'from' field of the email. | 
| MSGraphMail.From.Address | String | The email address of the user in the 'from' field of the email. | 
| MSGraphMail.CCRecipients.Name | String | The names of the users in the 'cc' field of the email. | 
| MSGraphMail.CCRecipients.Address | String | The email address of the user in the 'cc' field of the email. | 
| MSGraphMail.BCCRecipients.Name | String | The names of the users in the 'bcc' field of the email. | 
| MSGraphMail.BCCRecipients.Address | String | The email address of the user in the 'bcc' field of the email. | 
| MSGraphMail.ReplyTo.Name | String | The name in the 'replyTo' field of the email. | 
| MSGraphMail.ReplyTo.Address | String | The email address in the 'replyTo' field of the email. | 
| MSGraphMail.UserID | String | The ID of the user. | 
| MSGraphMail.ConversationID | String | The ID of the conversation. | 
| MSGraphMail.InternetMessageID | String | Internet Message ID of the message. | 
| MSGraphMail.Recipients.Name | String | The name of the user in the 'toRecipients' field of the email. | 
| MSGraphMail.Recipients.Address | String | The email address of the user in the 'toRecipients' field of the email. | 

### msgraph-mail-delete-email

***
Deletes an email.


#### Base Command

`msgraph-mail-delete-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| message_id | The unique ID of the mail. This could be extracted from - msgraph-mail-list-emails command results. You cannot use the the 'MessageID' key in the form '&lt;message-id&gt;'. | Required | 
| folder_id | A comma-separated list of folder IDs. For example, mailFolders,childFolders,childFolders. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

There is no context output for this command.

### msgraph-mail-list-attachments

***
Lists all of the attachments of given email


#### Base Command

`msgraph-mail-list-attachments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| message_id | The unique ID of the mail. You cannot use the the 'MessageID' key in the form '&lt;message-id&gt;'. | Required | 
| folder_id |  A comma-separated list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box). | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMailAttachment.ID | String | The email ID. | 
| MSGraphMailAttachment.Attachment.ID | String | The ID of the attachment. | 
| MSGraphMailAttachment.Attachment.Name | String | The name of the attachment. | 
| MSGraphMailAttachment.Attachment.Type | String | The attachment type. | 
| MSGraphMailAttachment.UserID | String | The ID of the user. | 

### msgraph-mail-get-attachment

***
Gets an attachment from the email.


#### Base Command

`msgraph-mail-get-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| message_id | The unique ID of the mail. You cannot use the the 'MessageID' key in the form '&lt;message-id&gt;'. | Required | 
| folder_id | A comma-separated list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box). | Optional | 
| attachment_id | The ID of the attachment. In case it is not supplied, the command will return all the attachments. | Optional | 
| ran_once_flag | flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

### msgraph-mail-list-folders

***
Returns the mail folder list directly under the root folder.


#### Base Command

`msgraph-mail-list-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| limit | The maximum number of mail folder lists to return. Default is 20. | Optional | 
| ran_once_flag | flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | Number | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | String | The folder display name. | 
| MSGraphMail.Folders.ID | String | The target folder ID. | 
| MSGraphMail.Folders.ParentFolderID | String | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | Number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | Number | The number of unread emails in the folder. | 

### msgraph-mail-list-child-folders

***
Returns the folder list under the specified folder.


#### Base Command

`msgraph-mail-list-child-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| parent_folder_id | The ID of the parent folder. | Required | 
| limit | The maximum number of mail folder lists to return. Default is 20. | Optional | 
| ran_once_flag | flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | Number | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | String | The folder display name. | 
| MSGraphMail.Folders.ID | String | The folder ID. | 
| MSGraphMail.Folders.ParentFolderID | String | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | Number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | Number | The number of unread email messages in the folder. | 

### msgraph-mail-create-folder

***
Creates a new folder under the specified folder (parent).


#### Base Command

`msgraph-mail-create-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| new_folder_name | The display name of the new folder. | Required | 
| parent_folder_id | The ID of the parent folder under which to create a new folder. | Optional | 
| ran_once_flag | flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | Number | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | String | The folder display name. | 
| MSGraphMail.Folders.ID | String | The folder ID. | 
| MSGraphMail.Folders.ParentFolderID | String | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | Number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | Number | The number of unread email messages in the folder. | 

### msgraph-mail-update-folder

***
Updates the properties of the specified folder.


#### Base Command

`msgraph-mail-update-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| folder_id | The ID of the folder to update. | Required | 
| new_display_name | The mail folder display name. | Required | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | String | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | String | The folder display name. | 
| MSGraphMail.Folders.ID | String | The folder ID. | 
| MSGraphMail.Folders.ParentFolderID | String | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | Number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | Number | The unread emails count inside the folder. | 

### msgraph-mail-delete-folder

***
Deletes the specified mail folder.


#### Base Command

`msgraph-mail-delete-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| folder_id | The ID of the folder to delete. | Required | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

There is no context output for this command.

### msgraph-mail-move-email

***
Moves a message to a different folder.


#### Base Command

`msgraph-mail-move-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The unique ID of the mail. You cannot use the the 'MessageID' key in the form '&lt;message-id&gt;'. | Required | 
| destination_folder_id | The ID of the destination folder. | Required | 
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.MovedEmails.DestinationFolderID | String | The folder where the email message was moved. | 
| MSGraphMail.MovedEmails.ID | String | The new ID of the moved email message. | 
| MSGraphMail.MovedEmails.UserID | String | The user ID. | 

### msgraph-mail-get-email-as-eml

***
Retrieves an email message by message ID and uploads the content as an EML file.


#### Base Command

`msgraph-mail-get-email-as-eml`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| message_id | The unique ID of the mail. You cannot use the the 'MessageID' key in the form '&lt;message-id&gt;'. | Required | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | String | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The EntryID of the file. | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

### msgraph-mail-create-draft

***
Creates a draft message in the specified user's mailbox.


#### Base Command

`msgraph-mail-create-draft`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | A comma-separated list of email addresses for the 'to' field. | Optional | 
| cc | A comma-separated list of email addresses for the 'cc' field. | Optional | 
| bcc | A comma-separated list of email addresses for the 'bcc' field. | Optional | 
| subject | The subject for the draft. | Required | 
| body | The contents (body) of the draft. | Optional | 
| bodyType | The body type of the email. Can be: "text", or "HTML". Possible values are: text, HTML. Default is text. | Optional | 
| flag | The flag value that indicates the status of the draft. Can be: "notFlagged", "complete", or "flagged". Possible values are: notFlagged, complete, flagged. Default is notFlagged. | Optional | 
| importance | The importance of the draft. Can be: "Low", "Normal", or "High". Possible values are: Low, Normal, High. Default is Low. | Optional | 
| headers | A comma-separated list of additional headers in the format, headerName:headerValue. For example, "headerName1:headerValue1,headerName2:headerValue2". | Optional | 
| attachIDs | A comma-separated list of War Room entry IDs that contain files, which are used to attach files to the draft. For example, attachIDs=15@8,19@8. | Optional | 
| attachNames | A comma-separated list of names of attachments to be displayed in the draft. Must be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A comma-separated list of CIDs to embed attachments within the actual email. | Optional | 
| from | The email address from which the draft is created. | Required | 
| ran_once_flag | flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftGraph.Draft.Cc | String | The CC recipients of the draft email. | 
| MicrosoftGraph.Draft.IsRead | String | The "Is read" status of the draft email. | 
| MicrosoftGraph.Draft.Bcc | String | The BCC recipients of the draft email. | 
| MicrosoftGraph.Draft.Body | String | The body of the draft email. | 
| MicrosoftGraph.Draft.MessageID | String | The message ID of the draft email. | 
| MicrosoftGraph.Draft.SentTime | Date | The created time of the draft email. | 
| MicrosoftGraph.Draft.Headers | String | The headers of the draft email. | 
| MicrosoftGraph.Draft.From | String | The user that sent the draft email. | 
| MicrosoftGraph.Draft.Subject | String | The subject of the draft email. | 
| MicrosoftGraph.Draft.ReceivedTime | String | The received time of the draft email. | 
| MicrosoftGraph.Draft.Importance | String | The importance status of the draft email. | 
| MicrosoftGraph.Draft.CreatedTime | String | The created time of the draft email. | 
| MicrosoftGraph.Draft.Sender | String | The sender of the draft email. | 
| MicrosoftGraph.Draft.ModifiedTime | Date | The modified time of the draft email. | 
| MicrosoftGraph.Draft.IsDraft | Boolean | Whether it is a draft email. | 
| MicrosoftGraph.Draft.ID | String | The ID of the draft email. | 
| MicrosoftGraph.Draft.To | String | The 'to' recipients of the draft email. | 
| MicrosoftGraph.Draft.BodyType | Unknown | The body type of the draft email. | 
| MicrosoftGraph.Draft.ConversationID | String | The conversation ID of the draft email. | 

### send-mail

***
Sends an email using Microsoft Graph.
Note: The *from* argument needs to be specified when the *Email address from which to fetch incidents* parameter is missing.

#### Base Command

`send-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | A comma-separated list of email addresses for the 'to' field. | Optional | 
| cc | A comma-separated list of email addresses for the 'cc' field. | Optional | 
| bcc | A comma-separated list of email addresses for the 'bcc' field. | Optional | 
| subject | The subject of the email. | Required | 
| body | The contents (body) of the email. | Optional | 
| bodyType | The body type of the email. Possible values are: text, HTML. | Optional | 
| flag | The flag value that indicates the status for the email. Possible values are: notFlagged, complete, flagged. Default is notFlagged. | Optional | 
| importance | The importance of the email. Possible values are: Low, Normal, High. Default is Low. | Optional | 
| headers | A comma-separated list of additional headers in the format: headerName:headerValue. For example: "headerName1:headerValue1,headerName2:headerValue2". | Optional | 
| attachIDs | A comma-separated list of War Room entry IDs that contain files, which are used to attach files for the email to send. For example, attachIDs=15@8,19@8. | Optional | 
| attachNames | A comma-separated list of names of attachments to display in the email to send. Must be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A comma-separated list of CIDs to embed attachments within the actual email. | Optional | 
| from | The email address from which to send the email. | Optional | 
| htmlBody | The content (body) of the email (in HTML format). | Optional | 
| replyTo | Email addresses that need to be used to reply to the message. Supports comma-separated values. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftGraph.Email.internetMessageHeaders | String | The email headers. | 
| MicrosoftGraph.Email.body | String | The body of the email. | 
| MicrosoftGraph.Email.bodyPreview | String | The body preview of the email. | 
| MicrosoftGraph.Email.subject | String | The subject of the email. | 
| MicrosoftGraph.Email.flag | String | The flag status of the email. | 
| MicrosoftGraph.Email.importance | String | The importance status of the email. | 
| MicrosoftGraph.Email.toRecipients | String | The 'to' recipients of the email. | 
| MicrosoftGraph.Email.ccRecipients | String | The CC recipients of the email. | 
| MicrosoftGraph.Email.bccRecipients | String | The BCC recipients of the email. | 
| MicrosoftGraph.Email.replyTo | String | The replyTo recipients of the email. | 

### msgraph-mail-reply-to

***
The replies to the recipients of a message.


#### Base Command

`msgraph-mail-reply-to`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ID | The ID of the message. | Required | 
| body | The comment of the replied message. | Required | 
| to | A comma-separated list of email addresses for the 'to' field. | Required | 
| from | The email address from which to reply. | Required | 
| attachIDs | A comma-separated list of War Room entry IDs that contain files, which are used to attach files for the email to send. For example, attachIDs=15@8,19@8. | Optional | 
| attachNames | A comma-separated list of names of attachments to display in the email to send. Must be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A CSV list of CIDs to embed attachments within the email itself. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

There is no context output for this command.

### msgraph-mail-send-draft

***
Sends a draft email using Microsoft Graph.


#### Base Command

`msgraph-mail-send-draft`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| draft_id | The ID of the draft email. | Required | 
| from | The email address from which to send the draft. | Required | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

There is no context output for this command.

### reply-mail

***
Replies to an email using Graph Mail.


#### Base Command

`reply-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | A CSV list of email addresses for the 'to' field. | Required | 
| body | The contents (body) of the email to be sent. | Optional | 
| subject | Subject for the email to be sent. | Required | 
| inReplyTo | ID of the item to reply to. | Required | 
| attachIDs | A CSV list of War Room entry IDs that contain files, and are used to attach files to the outgoing email. For example: attachIDs=15@8,19@8. | Optional | 
| cc | A CSV list of email addresses for the 'cc' field. | Optional | 
| bcc | A CSV list of email addresses for the 'bcc' field. | Optional | 
| htmlBody | HTML formatted content (body) of the email to be sent. This argument overrides the "body" argument. | Optional | 
| attachNames | A CSV list of names of attachments to send. Should be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A CSV list of CIDs to embed attachments within the email itself. | Optional | 
| from | Email address of the sender. | Optional | 
| replyTo | Email addresses that need to be used to reply to the message. Supports comma-separated values. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftGraph.SentMail.body | String | The body of the email. | 
| MicrosoftGraph.SentMail.bodyPreview | String | The body preview of the email. | 
| MicrosoftGraph.SentMail.subject | String | The subject of the email. | 
| MicrosoftGraph.SentMail.toRecipients | String | The 'To' recipients of the email. | 
| MicrosoftGraph.SentMail.ccRecipients | String | The CC recipients of the email. | 
| MicrosoftGraph.SentMail.bccRecipients | String | The BCC recipients of the email. | 
| MicrosoftGraph.SentMail.ID | String | The immutable ID of the message. | 
| MicrosoftGraph.SentMail.replyTo | String | The replyTo recipients of the email. | 

### msgraph-mail-update-email-status

***
Update the status of an email to read / unread.


#### Base Command

`msgraph-mail-update-email-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address. E.g., user@example.com). | Required | 
| message_ids | Unique ID of the emails to update. You cannot use the 'MessageID' key in the form '&lt;message-id&gt;'. Can be a list of comma-separated values. | Required | 
| folder_id | The folder ID. | Optional | 
| status | Status to set the email to. Possible values are: Read, Unread. | Required | 


#### Context Output

There is no context output for this command.


### msgraph-mail-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`msgraph-mail-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### msgraph-mail-list-rules

***
List email rules for a user's mailbox using Microsoft Graph API.

#### Base Command

`msgraph-mail-list-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| limit | Maximum number of results to return. Default is 50. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Rule.conditions | Unknown | Conditions that when fulfilled, will trigger the corresponding actions for that rule. | 
| MSGraphMail.Rule.actions | Unknown | Actions to be taken on a message when the corresponding conditions are fulfilled. | 
| MSGraphMail.Rule.displayName | String | The display name of the rule. | 
| MSGraphMail.Rule.exceptions | Unknown | Exception conditions for the rule. | 
| MSGraphMail.Rule.hasError | Boolean | Indicates whether the rule is in an error condition. | 
| MSGraphMail.Rule.id | String | The ID of the rule. | 
| MSGraphMail.Rule.isEnabled | Boolean | Indicates whether the rule is enabled to be applied to messages. | 
| MSGraphMail.Rule.isReadOnly | Boolean | Indicates if the rule is read-only and cannot be modified or deleted by the rules REST API. | 
| MSGraphMail.Rule.sequence | Number | Indicates the order in which the rule is executed, among other rules. | 
### msgraph-mail-get-rule

***
Get details of a specific email rule by ID for a user's mailbox using Microsoft Graph API.

#### Base Command

`msgraph-mail-get-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| rule_id | The ID of the rule to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Rule.conditions | Unknown | Conditions that when fulfilled, will trigger the corresponding actions for that rule. | 
| MSGraphMail.Rule.actions | Unknown | Actions to be taken on a message when the corresponding conditions are fulfilled. | 
| MSGraphMail.Rule.displayName | String | The display name of the rule. | 
| MSGraphMail.Rule.exceptions | Unknown | Exception conditions for the rule. | 
| MSGraphMail.Rule.hasError | Boolean | Indicates whether the rule is in an error condition. | 
| MSGraphMail.Rule.id | String | The ID of the rule. | 
| MSGraphMail.Rule.isEnabled | Boolean | Indicates whether the rule is enabled to be applied to messages. | 
| MSGraphMail.Rule.isReadOnly | Boolean | Indicates if the rule is read-only and cannot be modified or deleted by the rules REST API. | 
| MSGraphMail.Rule.sequence | Number | Indicates the order in which the rule is executed, among other rules. | 
### msgraph-mail-delete-rule

***
Delete a specific email rule by ID for a user's mailbox using Microsoft Graph API.

#### Base Command

`msgraph-mail-delete-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (usually an email address in the format someuser@example.com). | Required | 
| rule_id | The ID of the rule to delete. | Required | 

#### Context Output

There is no context output for this command.