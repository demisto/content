Microsoft Graph grants Cortex XSOAR authorized access to a user's Microsoft Outlook mail data in a personal account or organization account.
This integration was integrated and tested with version 1.0 of Microsoft Graph Mail Single User


## Fetch Incidents

The integration imports email messages from the destination folder in the target mailbox as incidents. If the message contains any attachments, they are uploaded to the War Room as files. If the attachment is an email (item attachment), Cortex XSOAR fetches information about the attached email and downloads all of its attachments (if there are any) as files. To use Fetch incidents, configure a new instance and select the Fetches incidents option in the instance settings.

## OData Usage

The OData parameter can be used to create different queries for the `msgraph-mail-list-emails` and `msgraph-mail-get-email` commands. Please see [OData Docs](https://docs.microsoft.com/en-us/graph/query-parameters) for detailed information.
Examples:
!msgraph-mail-list-emails odata=&quot;$select=from&quot;
!msgraph-mail-list-emails odata=&quot;$filter=from/emailAddress/address eq &#39;azure-noreply@microsoft.com&#39;&quot;
!msgraph-mail-list-emails odata=&quot;$filter=sentDateTime gt 2020-03-25T09:35:23Z and sentDateTime lt 2020-03-25T12:04:47Z&quot;

Note:
The query parameter `$filter` is not supported when using the `search` parameter.

## Authentication

For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).

**Note** - The credentials (created by the Cortex XSOAR application) are valid for a single instance only.


## Email Attachments Limitations

* The maximum attachment size to be sent in an email can be 150-MB. [large-attachments](https://docs.microsoft.com/en-us/graph/outlook-large-attachments?tabs=http)
* The larger the attachment, the longer it would take for a command that supports adding attachments to run.
* Requires the permission of Mail.ReadWrite (Application) - to send attachments > 3mb
* When sending mails with large attachments, it could take up to 5 minutes for the mail to actually be sent.

### Required Permissions

The following permissions are required for all commands:

* Mail.ReadWrite - Delegated
* Mail.Send - Delegated
* User.Read - Delegated 
* MailboxSettings.ReadWrite - Delegated 

The following permissions are required for Shared Mailbox:

* Mail.Read.Shared
* Mail.ReadBasic.Shared
* Mail.ReadWrite.Shared
* Mail.Send.Shared

## Configure Microsoft Graph Mail Single User in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ID or Client ID |  | False |
| Token or Tenant ID |  | False |
| Key or Client Secret |  | False |
| ID or Client ID - see Detailed Instructions (?) |  | False |
| Token or Tenant ID - see Detailed Instructions (?) |  | False |
| Key or Client Secret - see Detailed Instructions (?) |  | False |
| Certificate Thumbprint (optional for self-deployed Azure app) |  | False |
| Private Key |  | False |
| Certificate Thumbprint (optional for self-deployed Azure app) | Used for certificate authentication. As appears in the "Certificates &amp; secrets" page of the app. | False |
| Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
| Authorization code (required for self-deployed Azure app) |  | False |
| Application redirect URI (required for self-deployed Azure app) |  | False |
| Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
| Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
| Fetch incidents |  | False |
| Email address from which to fetch incidents (e.g., "example@demisto.com") | During authentication, ensure you are logged in to this email address. | True |
| Name of the folder from which to fetch incidents (supports Folder ID and sub-folders e.g., Inbox/Phishing) |  | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Maximum number of emails to pull per fetch |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Use a self-deployed Azure application | Select this checkbox if you are using a self-deployed Azure application. | False |
| Incident type |  | False |
| Display full email body | If not active, only a preview of the email will be fetched. | False |
| Fetch emails in HTML format | Select this checkbox to retrieve the body of an email in HTML format. If this checkbox is not selected, a psuedo-text representation of HTML emails will be returned and some functionality in other packs (e.g., email previews in the Email Communication pack) may not provide their full capabilities. | False |
| Mark fetched emails as read | Relevant only if fetch incidents is active. | False |
| Incidents Fetch Interval |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

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
| body_type | The body type of the email. Can be: "text", or "HTML". Possible values are: text, HTML. Default is text. | Optional | 
| flag | The flag value that indicates the status of the draft. Possible values are: notFlagged, complete, flagged. Default is notFlagged. | Optional | 
| importance | The importance of the draft. Possible values are: Low, Normal, High. Default is Low. | Optional | 
| headers | A comma-separated list of additional headers in the format, headerName:headerValue. For example, "headerName1:headerValue1,headerName2:headerValue2". | Optional | 
| attach_ids | A comma-separated list of War Room entry IDs that contain files, which are used to attach files to the draft. For example, attachIDs=15@8,19@8. | Optional | 
| attach_names | A comma-separated list of names of attachments to be displayed in the draft. Must be the same number of elements as attachIDs. | Optional | 
| attach_cids | A comma-separated list of CIDs to embed attachments within the actual email. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftGraph.Draft.Cc | String | The CC recipients of the draft email. | 
| MicrosoftGraph.Draft.IsRead | String | The "Is read" status of the draft email. | 
| MicrosoftGraph.Draft.Bcc | String | The BCC recipients of the draft email. | 
| MicrosoftGraph.Draft.Body | String | The body of the draft email. | 
| MicrosoftGraph.Draft.MessageID | String | The message ID of the draft email. | 
| MicrosoftGraph.Draft.SentTime | Date | The sent time of the draft email. | 
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

### reply-mail

***
Replies to an email using Graph Mail Single User.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.Send (Application)
- Mail.ReadWrite (Application) - to send attachments > 3mb
#### Base Command

`reply-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | A comma-separated list of email addresses for the 'to' field. | Required | 
| body | The contents (body) of the email to be sent. | Optional | 
| subject | Subject for the email to be sent. | Required | 
| inReplyTo | ID of the item to reply to. | Required | 
| attachIDs | A comma-separated list of War Room entry IDs that contain files, and are used to attach files to the outgoing email. For example: attachIDs=15@8,19@8. | Optional | 
| cc | A comma-separated list of email addresses for the 'cc' field. | Optional | 
| bcc | A comma-separated list of email addresses for the 'bcc' field. | Optional | 
| htmlBody | HTML formatted content (body) of the email to be sent. This argument overrides the "body" argument. | Optional | 
| attachNames | A comma-separated list of names of attachments to send. Should be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A comma-separated list of CIDs to embed attachments within the email itself. | Optional | 
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

### send-mail

***
Sends an email using Microsoft Graph.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.Send (Application)
- Mail.ReadWrite (Application) - to send attachments > 3mb

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
| body_type | The body type of the email. Can be: "text", or "HTML". Possible values are: text, HTML. | Optional | 
| renderBody | Indicates whether to render the email body. Possible values are: true, false. | Optional | 
| flag | The flag value that indicates the status for the email. Possible values are: notFlagged, complete, flagged. Default is notFlagged. | Optional | 
| importance | The importance of the email. Possible values are: Low, Normal, High. Default is Low. | Optional | 
| headers | A comma-separated list of additional headers in the format: headerName:headerValue. For example: "headerName1:headerValue1,headerName2:headerValue2". | Optional | 
| attach_ids | A comma-separated list of War Room entry IDs that contain files, which are used to attach files for the email to send. For example, attachIDs=15@8,19@8. | Optional | 
| attach_names | A comma-separated list of names of attachments to display in the email to send. Must be the same number of elements as attachIDs. | Optional | 
| attach_cids | A comma-separated list of CIDs to embed attachments within the actual email. | Optional | 
| attachIDs | A comma-separated list of War Room entry IDs that contain files, which are used to attach files for the email to send. For example, attachIDs=15@8,19@8. | Optional | 
| attachNames | A comma-separated list of names of attachments to display in the email to send. Must be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A comma-separated list of CIDs to embed attachments within the actual email. | Optional | 
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
| message_id | The ID of the message. | Required | 
| comment | The comment of the replied message. | Required | 
| to | A comma-separated list of email addresses for the 'to' field. | Required | 
| attach_ids | A comma-separated list of War Room entry IDs that contain files, which are used to attach files for the email to send. For example, attachIDs=15@8,19@8. | Optional | 
| attach_names | A comma-separated list of names of attachments to display in the email to send. Must be the same number of elements as attach_ids. | Optional | 
| attach_cids | A comma-separated list of CIDs to embed attachments within the actual email. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 

#### Context Output

There is no context output for this command.

##### Command Example


### msgraph-mail-send-draft

***
Sends a draft email using Microsoft Graph.

#### Base Command

`msgraph-mail-send-draft`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| draft_id | The ID of the draft email. | Required | 
| ran_once_flag | Flag for rate limit retry. | Optional | 

#### Context Output

There is no context output for this command.
### msgraph-mail-test

***
Tests connectivity of the email.

#### Base Command

`msgraph-mail-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

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
### msgraph-mail-list-emails

***
Gets the properties of returned emails. Typically shows partial results, use the "page_size" and "pages_to_pull" arguments to get all results.

#### Base Command

`msgraph-mail-list-emails`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| odata | An OData query. See [OData Usage](#odata-usage) for OData usage examples. | Optional | 
| search | The term for which to search. This argument cannot contain reserved characters such as !, $, #, @, etc. For further information, see https://tools.ietf.org/html/rfc3986#section-2.2. | Optional | 
| page_size | The maximum number of emails to fetch in one request. Default is 20. | Optional | 
| pages_to_pull | The number of pages of emails to return (maximum is 10 emails per page). Default is 1. | Optional | 
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
| MSGraphMail.Subject | String | The subject of the email. | 
| MSGraphMail.IsDraft | Boolean | Whether the email is a draft. | 
| MSGraphMail.Body | String | The content \(body\) of the email. | 
| MSGraphMail.Sender.Name | String | The name of the sender. | 
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

### msgraph-mail-list-attachments

***
Lists all attachments of an email.

#### Base Command

`msgraph-mail-list-attachments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The email message id. | Required | 
| folder_id | The id of the folder. | Optional | 
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
| message_id | The unique ID of the mail. You cannot use the 'MessageID' key in the form '&lt;message-id&gt;'. | Required | 
| folder_id | A comma-separated list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box). | Optional | 
| attachment_id | The ID of the attachment. In case not supplied, the command will return all the attachments. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 

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

### msgraph-mail-get-email-as-eml

***
Retrieves an email message by message ID and uploads the content as an EML file.

#### Base Command

`msgraph-mail-get-email-as-eml`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The unique ID of the email. You cannot use the 'MessageID' key in the form '&lt;message-id&gt;'. | Required | 
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

### msgraph-update-email-status

***
Update the status of an email to read / unread.

#### Base Command

`msgraph-update-email-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_ids | Unique ID of the emails to update. You cannot use the 'MessageID' key in the form '&lt;message-id&gt;'. Can be a list of comma-separated values. | Required | 
| folder_id | The folder ID. | Optional | 
| status | Status to set the email to. Possible values are: Read, Unread. | Required | 

#### Context Output

There is no context output for this command.
### msgraph-mail-generate-login-url

***
Generate the login url used for Authorization code flow.

#### Base Command

`msgraph-mail-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```msgraph-mail-generate-login-url```

#### Human Readable Output

>### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.

### msgraph-mail-create-folder

***
Creates a new folder under the specified folder (parent).

#### Base Command

`msgraph-mail-create-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| new_folder_name | display name of new folder. | Required | 
| parent_folder_id | The ID of the parent folder under which to create a new folder. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | number | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | string | The folder display name. | 
| MSGraphMail.Folders.ID | string | The Folder ID. | 
| MSGraphMail.Folders.ParentFolderID | string | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | number | The number of unread email messages in the folder. | 

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
| ran_once_flag | Flag for rate limit retry. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.MovedEmails.DestinationFolderID | string | The folder where the email message was moved. | 
| MSGraphMail.MovedEmails.ID | string | The new ID of the moved email message. | 
| MSGraphMail.MovedEmails.UserID | unknown | The user ID. | 

### msgraph-mail-list-folders

***
Returns the mail folder list directly under the root folder.

#### Base Command

`msgraph-mail-list-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of mail folder lists to return. Default is 20. | Optional | 
| ran_once_flag | Flag for rate limit retry. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | number | Number of child folders. | 
| MSGraphMail.Folders.DisplayName | string | Folder display name. | 
| MSGraphMail.Folders.ID | string | Target folder ID. | 
| MSGraphMail.Folders.ParentFolderID | string | Parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | number | The number of unread emails in the folder. | 

### msgraph-mail-list-child-folders

***
Returns the folder list under the specified folder.

#### Base Command

`msgraph-mail-list-child-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent_folder_id | The ID of the parent folder. | Required | 
| limit | The maximum number of mail folder lists to return. Default is 20. Default is 20. | Optional | 
| ran_once_flag | Flag for the rate limit retry. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | Number | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | String | The folder display name. | 
| MSGraphMail.Folders.ID | String | The folder ID. | 
| MSGraphMail.Folders.ParentFolderID | String | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | Number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | Number | The number of unread email messages in the folder. | 
### msgraph-mail-list-rules

***
List email rules for a user's mailbox using Microsoft Graph API.

#### Base Command

`msgraph-mail-list-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
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
| rule_id | The ID of the rule to delete. | Required | 

#### Context Output

There is no context output for this command.

## Troubleshooting

In case of a **hash verification** error:
1. Use the Oproxy flow to generate a new pair of credentials. This is crucial as it ensures that any issues related to authentication can be mitigated with fresh credentials.
2. Execute the command ***!msgraph-mail-auth-reset***. This command resets the authentication mechanism, allowing for the new credentials to be accepted.
3. Insert the newly created credentials into the original instance where the error occurred. Make sure the credentials are entered correctly to avoid further errors.
4. After updating the credentials, test the integration.