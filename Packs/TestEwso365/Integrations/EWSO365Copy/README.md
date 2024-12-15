The new EWS O365 integration uses OAuth 2.0 protocol and can be used with Exchange Online and Office 365 (mail).
## Configure EWSO365_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EWSO365_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Azure Cloud | More information about National clouds can be found here - https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication\#using-national-cloud | False |
    | ID / Application ID | ID can be received from the admin consent procedure - see Detailed Instructions. | False |
    | Token / Tenant ID | Token can be received from the admin consent procedure - see Detailed Instructions. | False |
    | Key / Application Secret | Key can be received from the admin consent procedure - see Detailed Instructions. | False |
    | Email Address | Mailbox to run commands on and to fetch incidents from. To use this functionality, your account must have impersonation rights or delegation for the account specified. For more information, see https://xsoar.pan.dev/docs/reference/integrations/ewso365\#additional-information | True |
    | UPN Address | If this parameter is given, the commands will run with the UPN mailbox instead of the default target mailbox. | False |
    | Name of the folder from which to fetch incidents | Supports Exchange Folder ID and sub-folders e.g. Inbox/Phishing. | True |
    | Access Type |  | False |
    | Public Folder |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Maximum number of incidents per fetch (up to 200). Performance might be affected by a value higher than 50. |  | False |
    | Mark fetched emails as read |  | False |
    | Timeout (in seconds) for HTTP requests to Exchange Server |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Run as a separate process (protects against memory depletion) |  | False |
    | Use a self deployed Azure Application | Select this checkbox if you are using a self-deployed Azure application. | False |
    | ID / Application ID (Deprecated) | Use the "ID" parameter instead. | False |
    | Token / Tenant ID (Deprecated) | Use the "Token" parameter instead. | False |
    | Key / Application Secret (Deprecated) | Use the "Key" parameter instead. | False |
    | Incidents Fetch Interval |  | False |
    | What time field should we filter incidents by? | Default is to filter by received-time, which works well if the folder is an "Inbox". But for a folder emails are dragged into for attention, if we filter by received-time, out-of-order processing of emails means some are ignored. Filtering by modified-time works better for such a scenario. This works best if any modifications \(such as tagging\) happens before moving the email into the folder, such that the move into the folder is the last modification, and triggers Cortex XSOAR to fetch it as an incident. | False |
    | Use legacy attachment name |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ews-get-attachment

***
Retrieves the actual attachments from an item (email message). To get all attachments for a message, only specify the item-id argument.

#### Base Command

`ews-get-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-id | The ID of the email message for which to get the attachments. | Required | 
| target-mailbox | The mailbox in which this attachment was found. If empty, the default mailbox is used. Otherwise the user might require impersonation rights to this mailbox. | Optional | 
| attachment-ids | The attachments ids to get. If none - all attachments will be retrieve from the message. Support multiple attachments with comma-separated value or array. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.FileAttachments.attachmentId | string | The attachment ID. Used for file attachments only. | 
| EWS.Items.FileAttachments.attachmentName | string | The attachment name. Used for file attachments only. | 
| EWS.Items.FileAttachments.attachmentSHA256 | string | The SHA256 hash of the attached file. | 
| EWS.Items.FileAttachments.attachmentLastModifiedTime | date | The attachment last modified time. Used for file attachments only. | 
| EWS.Items.ItemAttachments.datetimeCreated | date | The created time of the attached email. | 
| EWS.Items.ItemAttachments.datetimeReceived | date | The received time of the attached email. | 
| EWS.Items.ItemAttachments.datetimeSent | date | The sent time of the attached email. | 
| EWS.Items.ItemAttachments.receivedBy | string | The received by address of the attached email. | 
| EWS.Items.ItemAttachments.subject | string | The subject of the attached email. | 
| EWS.Items.ItemAttachments.textBody | string | The body of the attached email \(as text\). | 
| EWS.Items.ItemAttachments.headers | Unknown | The headers of the attached email. | 
| EWS.Items.ItemAttachments.hasAttachments | boolean | Whether the attached email has attachments. | 
| EWS.Items.ItemAttachments.itemId | string | The attached email item ID. | 
| EWS.Items.ItemAttachments.toRecipients | Unknown | A list of recipient email addresses for the attached email. | 
| EWS.Items.ItemAttachments.body | string | The body of the attached email \(as HTML\). | 
| EWS.Items.ItemAttachments.attachmentSHA256 | string | The SHA256 hash of the attached email \(as EML file\). | 
| EWS.Items.ItemAttachments.FileAttachments.attachmentSHA256 | string | SHA256 hash of the attached files inside of the attached email. | 
| EWS.Items.ItemAttachments.ItemAttachments.attachmentSHA256 | string | SHA256 hash of the attached emails inside of the attached email. | 
| EWS.Items.ItemAttachments.isRead | String | The read status of the attachment. | 

### ews-delete-attachment

***
Deletes the attachments of an item (email message).

#### Base Command

`ews-delete-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-id | The ID of the email message for which to delete attachments. | Required | 
| target-mailbox | The mailbox in which this attachment was found. If empty, the default mailbox is used. Otherwise the user might require impersonation rights to this mailbox. | Optional | 
| attachment-ids | A comma-separated list (or array) of attachment IDs to delete. If empty, all attachments will be deleted from the message. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.FileAttachments.attachmentId | string | The ID of the deleted attachment, in case of file attachment. | 
| EWS.Items.ItemAttachments.attachmentId | string | The ID of the deleted attachment, in case of other attachment \(for example, "email"\). | 
| EWS.Items.FileAttachments.action | string | The deletion action in case of file attachment. This is a constant value: 'deleted'. | 
| EWS.Items.ItemAttachments.action | string | The deletion action in case of other attachment \(for example, "email"\). This is a constant value: 'deleted'. | 

### ews-get-searchable-mailboxes

***
Returns a list of searchable mailboxes. This command requires eDiscovery permissions to the Exchange Server. For more information, see the EWSv2 integration documentation.

#### Base Command

`ews-get-searchable-mailboxes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Mailboxes.mailbox | string | Addresses of the searchable mailboxes. | 
| EWS.Mailboxes.mailboxId | string | IDs of the searchable mailboxes. | 
| EWS.Mailboxes.displayName | string | The email display name. | 
| EWS.Mailboxes.isExternal | boolean | Whether the mailbox is external. | 
| EWS.Mailboxes.externalEmailAddress | string | The external email address. | 

### ews-move-item

***
Move an item to different folder in the mailbox.

#### Base Command

`ews-move-item`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-id | The ID of the item to move. | Required | 
| target-folder-path | The path to the folder to which to move the item. Complex paths are supported, for example, "Inbox\Phishing". | Required | 
| target-mailbox | The mailbox on which to run the command. | Optional | 
| is-public | Whether the target folder is a public folder. Can be "True" or "False". Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.newItemID | string | The item ID after move. | 
| EWS.Items.messageID | string | The item message ID. | 
| EWS.Items.itemId | string | The original item ID. | 
| EWS.Items.action | string | The action taken. The value will be "moved". | 

### ews-delete-items

***
Delete items from mailbox.

#### Base Command

`ews-delete-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-ids | The item IDs to delete. | Required | 
| delete-type | Deletion type. Can be "trash", "soft", or "hard". Default is soft. | Required | 
| target-mailbox | The mailbox on which to run the command. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.itemId | string | The deleted item ID. | 
| EWS.Items.messageId | string | The deleted message ID. | 
| EWS.Items.action | string | The deletion action. Can be 'trash-deleted', 'soft-deleted', or 'hard-deleted'. | 

### ews-search-mailbox

***
Searches for items in the specified mailbox. Specific permissions are needed for this operation to search in a target mailbox other than the default.

#### Base Command

`ews-search-mailbox`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search query string. For more information about the query syntax, see the Microsoft documentation: https://msdn.microsoft.com/en-us/library/ee693615.aspx. | Optional | 
| folder-path | The folder path in which to search. If empty, searches all folders in the mailbox. | Optional | 
| limit | Maximum number of results to return. The default is 50. Default is 50. | Optional | 
| target-mailbox | The mailbox on which to apply the search. | Optional | 
| is-public | Whether the folder is a public folder. Can be "True" or "False". Possible values are: True, False. | Optional | 
| message-id | The message ID of the email. This will be ignored if a query argument is provided. | Optional | 
| selected-fields | A comma-separated list of fields to retrieve. Possible values are: . Default is all. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.itemId | string | The email item ID. | 
| EWS.Items.hasAttachments | boolean | Whether the email has attachments. | 
| EWS.Items.datetimeReceived | date | Received time of the email. | 
| EWS.Items.datetimeSent | date | Sent time of the email. | 
| EWS.Items.headers | Unknown | Email headers \(list\). | 
| EWS.Items.sender | string | Sender email address of the email. | 
| EWS.Items.subject | string | Subject of the email. | 
| EWS.Items.textBody | string | Body of the email \(as text\). | 
| EWS.Items.size | number | Email size. | 
| EWS.Items.toRecipients | Unknown | List of email recipients addresses. | 
| EWS.Items.receivedBy | Unknown | Received by address of the email. | 
| EWS.Items.messageId | string | Email message ID. | 
| EWS.Items.body | string | Body of the email \(as HTML\). | 
| EWS.Items.FileAttachments.attachmentId | unknown | Attachment ID of the file attachment. | 
| EWS.Items.ItemAttachments.attachmentId | unknown | Attachment ID of the item attachment. | 
| EWS.Items.FileAttachments.attachmentName | unknown | Attachment name of the file attachment. | 
| EWS.Items.ItemAttachments.attachmentName | unknown | Attachment name of the item attachment. | 
| EWS.Items.isRead | String | The read status of the email. | 

### ews-get-contacts

***
Retrieves contacts for a specified mailbox.

#### Base Command

`ews-get-contacts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target-mailbox | The mailbox for which to retrieve the contacts. | Optional | 
| limit | Maximum number of results to return. The default is 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Email.EwsContacts.displayName | Unknown | The contact name. | 
| Account.Email.EwsContacts.lastModifiedTime | Unknown | The time that the contact was last modified. | 
| Account.Email.EwsContacts.emailAddresses | Unknown | Phone numbers of the contact. | 
| Account.Email.EwsContacts.physicalAddresses | Unknown | Physical addresses of the contact. | 
| Account.Email.EwsContacts.phoneNumbers.phoneNumber | Unknown | Email addresses of the contact. | 

### ews-get-out-of-office

***
Retrieves the out-of-office status for a specified mailbox.

#### Base Command

`ews-get-out-of-office`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target-mailbox | The mailbox for which to get the out-of-office status. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Email.OutOfOffice.state | Unknown | Out-of-office state. Result can be: Enabled, Scheduled, Disabled. | 
| Account.Email.OutOfOffice.externalAudience | Unknown | Out-of-office external audience. Can be "None", "Known", or "All". | 
| Account.Email.OutOfOffice.start | Unknown | Out-of-office start date. | 
| Account.Email.OutOfOffice.end | Unknown | Out-of-office end date. | 
| Account.Email.OutOfOffice.internalReply | Unknown | Out-of-office internal reply. | 
| Account.Email.OutOfOffice.externalReply | Unknown | Out-of-office external reply. | 
| Account.Email.OutOfOffice.mailbox | Unknown | Out-of-office mailbox. | 

### ews-recover-messages

***
Recovers messages that were soft-deleted.

#### Base Command

`ews-recover-messages`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message-ids | A comma-separated list of message IDs. Run the py-ews-delete-items command to retrieve the message IDs. | Required | 
| target-folder-path | The folder path to recover the messages to. Default is Inbox. | Required | 
| target-mailbox | The mailbox in which the messages found. If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox. | Optional | 
| is-public | Whether the target folder is a Public Folder. Can be "True" or "False". Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.itemId | Unknown | The item ID of the recovered item. | 
| EWS.Items.messageId | Unknown | The message ID of the recovered item. | 
| EWS.Items.action | Unknown | The action taken on the item. The value will be 'recovered'. | 

### ews-create-folder

***
Creates a new folder in a specified mailbox.

#### Base Command

`ews-create-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| new-folder-name | The name of the new folder. | Required | 
| folder-path | Path to locate the new folder. Exchange folder ID is also supported. Default is Inbox. | Required | 
| target-mailbox | The mailbox in which to create the folder. | Optional | 

#### Context Output

There is no context output for this command.
### ews-mark-item-as-junk

***
Marks an item as junk. This is commonly used to block an email address. For more information, see the Microsoft documentation: https://msdn.microsoft.com/en-us/library/office/dn481311(v=exchg.150).aspx.

#### Base Command

`ews-mark-item-as-junk`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-id | The item ID to mark as junk. | Required | 
| move-items | Whether to move the item from the original folder to the junk folder. Can be "yes" or "no". The default is "yes". Possible values are: yes, no. Default is yes. | Optional | 
| target-mailbox | If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox. | Optional | 

#### Context Output

There is no context output for this command.
### ews-find-folders

***
Retrieves information for folders for a specified mailbox. Only folders with read permissions will be returned. Your visual folders on the mailbox, such as "Inbox", are under the folder "Top of Information Store".

#### Base Command

`ews-find-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target-mailbox | The mailbox on which to apply the command. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Folders.name | string | Folder name. | 
| EWS.Folders.id | string | Folder ID. | 
| EWS.Folders.totalCount | Unknown | Number of items in the folder. | 
| EWS.Folders.unreadCount | number | Number of unread items in the folder. | 
| EWS.Folders.changeKey | number | Folder change key. | 
| EWS.Folders.childrenFolderCount | number | Number of sub-folders. | 

### ews-get-items-from-folder

***
Retrieves items from a specified folder in a mailbox. The items are order by the item created time, most recent is first.

#### Base Command

`ews-get-items-from-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder-path | The folder path from which to get the items. | Required | 
| limit | Maximum number of items to return. The default is 50. Default is 50. | Optional | 
| target-mailbox | The mailbox on which to apply the command. | Optional | 
| is-public | Whether the folder is a public folder. Can be "True" or "False". The default is "False". Possible values are: True, False. | Optional | 
| get-internal-item | If the email item contains another email as an attachment (EML or MSG file), whether to retrieve the EML/MSG file attachment. Can be "yes" or "no". The default is "no". Possible values are: yes, no. Default is no. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.itemId | string | The item ID of the email. | 
| EWS.Items.hasAttachments | boolean | Whether the email has attachments. | 
| EWS.Items.datetimeReceived | date | Received time of the email. | 
| EWS.Items.datetimeSent | date | Sent time of the email. | 
| EWS.Items.headers | Unknown | Email headers \(list\). | 
| EWS.Items.sender | string | Sender mail address of the email. | 
| EWS.Items.subject | string | Subject of the email. | 
| EWS.Items.textBody | string | Body of the email \(as text\). | 
| EWS.Items.size | number | Email size. | 
| EWS.Items.toRecipients | Unknown | Email recipients addresses \(list\). | 
| EWS.Items.receivedBy | Unknown | Received by address of the email. | 
| EWS.Items.messageId | string | Email message ID. | 
| EWS.Items.body | string | Body of the email \(as HTML\). | 
| EWS.Items.FileAttachments.attachmentId | unknown | Attachment ID of file attachment. | 
| EWS.Items.ItemAttachments.attachmentId | unknown | Attachment ID of the item attachment. | 
| EWS.Items.FileAttachments.attachmentName | unknown | Attachment name of the file attachment. | 
| EWS.Items.ItemAttachments.attachmentName | unknown | Attachment name of the item attachment. | 
| EWS.Items.isRead | String | The read status of the email. | 
| EWS.Items.categories | unknown | The categories of the email. | 

### ews-get-items

***
Retrieves items by item ID.

#### Base Command

`ews-get-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-ids | A comma-separated list of item IDs. | Required | 
| target-mailbox | The mailbox on which to run the command. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.itemId | string | The email item ID. | 
| EWS.Items.hasAttachments | boolean | Whether the email has attachments. | 
| EWS.Items.datetimeReceived | date | Received time of the email. | 
| EWS.Items.datetimeSent | date | Sent time of the email. | 
| EWS.Items.headers | Unknown | Email headers \(list\). | 
| EWS.Items.sender | string | Sender mail address of the email. | 
| EWS.Items.subject | string | Subject of the email. | 
| EWS.Items.textBody | string | Body of the email \(as text\). | 
| EWS.Items.size | number | Email size. | 
| EWS.Items.toRecipients | Unknown | Email recipients addresses \(list\). | 
| EWS.Items.receivedBy | Unknown | Received by address of the email. | 
| EWS.Items.messageId | string | Email message ID. | 
| EWS.Items.body | string | Body of the email \(as HTML\). | 
| EWS.Items.FileAttachments.attachmentId | unknown | Attachment ID of the file attachment. | 
| EWS.Items.ItemAttachments.attachmentId | unknown | Attachment ID of the item attachment. | 
| EWS.Items.FileAttachments.attachmentName | unknown | Attachment name of the file attachment. | 
| EWS.Items.ItemAttachments.attachmentName | unknown | Attachment name of the item attachment. | 
| EWS.Items.isRead | String | The read status of the email. | 
| Email.CC | String | Email addresses CC'ed to the email. | 
| Email.BCC | String | Email addresses BCC'ed to the email. | 
| Email.To | String | The recipient of the email. | 
| Email.From | String | The sender of the email. | 
| Email.Subject | String | The subject of the email. | 
| Email.Text | String | The plain-text version of the email. | 
| Email.HTML | String | The HTML version of the email. | 
| Email.HeadersMap | String | The headers of the email. | 
| EWS.Items.categories | unknown | The categories of the email. | 

### ews-move-item-between-mailboxes

***
Moves an item from one mailbox to different mailbox.

#### Base Command

`ews-move-item-between-mailboxes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-id | The item ID to move. | Required | 
| destination-folder-path | The folder in the destination mailbox to which to move the item. You can specify a complex path, for example, "Inbox\Phishing". | Required | 
| destination-mailbox | The mailbox to which to move the item. | Required | 
| source-mailbox | The mailbox from which to move the item (conventionally called the "target-mailbox", the target mailbox on which to run the command). | Optional | 
| is-public | Whether the destination folder is a Public Folder. Can be "True" or "False". Default is "False". Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.movedToMailbox | string | The mailbox wo which the item was moved. | 
| EWS.Items.movedToFolder | string | The folder to which the item was moved. | 
| EWS.Items.action | string | The action taken on the item. The value will be "moved". | 

### ews-get-folder

***
Retrieves a single folder.

#### Base Command

`ews-get-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target-mailbox | The mailbox on which to run the search. | Optional | 
| folder-path | The path of the folder to retrieve. If empty, will retrieve the folder "AllItems". Default is AllItems. | Optional | 
| is-public | Whether the folder is a Public Folder. Default is "False". Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Folders.id | string | Folder ID. | 
| EWS.Folders.name | string | Folder name. | 
| EWS.Folders.changeKey | string | Folder change key. | 
| EWS.Folders.totalCount | number | Total number of emails in the folder. | 
| EWS.Folders.childrenFolderCount | number | Number of sub-folders. | 
| EWS.Folders.unreadCount | number | Number of unread emails in the folder. | 

### ews-expand-group

***
Expands a distribution list to display all members. By default, expands only first layer of the distribution list. If recursive-expansion is "True", the command expands nested distribution lists and returns all members.

#### Base Command

`ews-expand-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email-address | Email address of the group to expand. | Required | 
| recursive-expansion | Whether to enable recursive expansion. Can be "True" or "False". Default is "False". Possible values are: True, False. Default is False. | Optional | 

#### Context Output

There is no context output for this command.
### ews-mark-items-as-read

***
Marks items as read or unread.

#### Base Command

`ews-mark-items-as-read`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-ids | A comma-separated list of item IDs. | Required | 
| operation | How to mark the item. Can be "read" or "unread". Default is "read". Possible values are: read, unread. Default is read. | Optional | 
| target-mailbox | The mailbox on which to run the command. If empty, the command will be applied on the default mailbox. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.action | String | The action that was performed on item. | 
| EWS.Items.itemId | String | The ID of the item. | 
| EWS.Items.messageId | String | The message ID of the item. | 

### ews-get-items-as-eml

***
Retrieves items by item ID and uploads its content as an EML file.

#### Base Command

`ews-get-items-as-eml`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-id | The item ID of the item to upload as an EML file. | Required | 
| target-mailbox | The mailbox in which this email was found. If empty, the default mailbox is used. Otherwise the user might require impersonation rights to this mailbox. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | String | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | EntryID of the file. | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

### send-mail

***
Sends an email.

#### Base Command

`send-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Email addresses for the 'To' field. Supports comma-separated values. | Optional | 
| cc | Email addresses for the 'Cc' field. Supports comma-separated values. | Optional | 
| bcc | Email addresses for the 'Bcc' field. Supports comma-separated values. | Optional | 
| subject | The email subject. | Optional | 
| body | The content (body) of the email (in plain text). | Optional | 
| htmlBody | The content (body) of the email (in HTML format). | Optional | 
| attachIDs | A comma-separated list of War Room entry IDs that contain the files to attach to the email. | Optional | 
| attachNames | A comma-separated list to rename file names of corresponding attachment IDs. For example, rename the first two files - attachNames=file_name1,file_name2. rename first and third file - attachNames=file_name1,,file_name3). | Optional | 
| attachCIDs | A comma-separated list of CIDs to embed attachments inside the email itself. | Optional | 
| transientFile | A name for the attached file. You can pass multiple files in a comma-separated list, e.g., transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz". | Optional | 
| transientFileContent | Content for the attached file. You can pass multiple files in a comma-separated list, e.g., transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz". | Optional | 
| transientFileCID | CID for the attached file if it's inline. You can pass multiple files in a comma-separated list, e.g., transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz". | Optional | 
| templateParams | Replace {varname} variables with values from this argument. Expected values are in the form of a JSON document, such ase {"varname": {"value": "some value", "key": "context key"}}. Each var name can either be provided with the value or a context key from which to retrieve the value. Note that only context data is accessible for this argument, while incident fields are not. | Optional | 
| additionalHeader | A comma-separated list of additional headers in the format: headerName=headerValue. For example: "headerName1=headerValue1,headerName2=headerValue2". | Optional | 
| raw_message | Raw email message. If provided, all other arguments will be ignored except "to", "cc", and "bcc". | Optional | 
| from | The email address from which to reply. | Optional | 
| replyTo | Email addresses that need to be used to reply to the message. Supports comma-separated values. | Optional | 
| importance | Sets the importance/Priority of the email. Default value is Normal. Possible values are: High, Normal, Low. Default is Normal. | Optional | 

#### Context Output

There is no context output for this command.
### reply-mail

***
Replies to an email using EWS.

#### Base Command

`reply-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inReplyTo | ID of the item to reply to. | Required | 
| to | A comma-separated list of email addresses for the 'to' field. | Required | 
| cc | A comma-separated list of email addresses for the 'cc' field. | Optional | 
| bcc | A comma-separated list of email addresses for the 'bcc' field. | Optional | 
| subject | Subject for the email to be sent. | Optional | 
| body | The contents (body) of the email to be sent. | Optional | 
| htmlBody | HTML formatted content (body) of the email to be sent. This argument overrides the "body" argument. | Optional | 
| renderBody | Indicates whether to render the email body. Possible values are: true, false. | Optional | 
| attachIDs | A comma-separated list of War Room entry IDs that contain files, and are used to attach files to the outgoing email. For example: attachIDs=15@8,19@8. | Optional | 
| attachNames | A comma-separated list of names of attachments to send. Should be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A comma-separated list of CIDs to embed attachments within the email itself. | Optional | 

#### Context Output

There is no context output for this command.
### ews-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`ews-auth-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
