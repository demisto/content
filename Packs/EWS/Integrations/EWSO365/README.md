Exchange Web Services (EWS) provides the functionality to enable client applications to communicate with the Exchange server. EWS provides access to much of the same data that is made available through Microsoft OfficeOutlook.

The EWS O365 integration implants EWS leading services. The integration allows getting information on emails and activities in a target mailbox, and some active operations on the mailbox such as deleting emails and attachments or moving emails from folder to folder.

## EWS O365 Playbook

*   Get Original Email - EWS
*   Process Email - EWS

## Use Cases

The EWS integration can be used for the following use cases.

*   Monitor a specific email account and create incidents from incoming emails to the defined folder.  
    Follow the instructions in the Fetched Incidents Data section.

*   Search for an email message across mailboxes and folders.  
    This can be achieved in the following ways:

    1.  Use the `ews-search-mailbox` command to search for all emails in a specific folder within the target mailbox.  
        Use the query argument to narrow the search for emails sent from a specific account and more.
    *   This command retrieve the _ItemID_ field for each email item listed in the results. The `ItemID` can be used in the `ews-get-items` command in order to get more information about the email item itself.
*   Get email attachment information.  
    Use the `ews-get-attachment` command to retrieve information on one attachment or all attachments of a message at once. It supports both file attachments and item attachments (e.g., email messages).

*   Delete email items from a mailbox.  
    First, make sure you obtain the email item ID. The item ID can be obtained with one of the integration’s search commands.  
    Use the `ews-delete-items`<span> command </span>to delete one or more items from the target mailbox in a single action.  
    A less common use case is to remove emails that were marked as malicious from a user’s mailbox.  
    You can delete the items permanently (hard delete), or delete the items (soft delete), so they can be recovered by running the `ews-recover-messages` command.

## Configure EWS O365 on Demisto

1.  Navigate to **Settings** > **Integrations** > **Servers & Services**.
2.  Search for EWS O365.
3.  Click **Add instance** to create and configure a new integration instance.
    *   **Name**: a textual name for the integration instance.
    *   **ID / Application ID**: ID recieved from https://oproxy.demisto.ninja/ms-ews-o365 app registration, or a self deployed Application ID.
    *   **Token / Tenant ID**: Token recieved from https://oproxy.demisto.ninja/ms-ews-o365 app registration, or a self deployed Application Tenant ID.
    *   **Key / Application Secret**: Key recieved from https://oproxy.demisto.ninja/ms-ews-o365 app registration, or a self deployed Application Secret.
    *   **Email Address**: Mailbox to run commands on, and to fetch incidents from. This argument can take various user accounts in your organization. Usually is used as phishing mailbox.  
        Note: To use this functionality, your account must have impersonation rights or delegation for the account specified. For more information on impersonation rights see ‘Additional Information’ section below.
    *   **Name of the folder from which to fetch incidents**: Supports Exchange Folder ID and sub-folders e.g. Inbox/Phishing. Please note, if Exchange is configured with an international flavor `Inbox` will be named according to the configured language.
    *   **Public Folder**
    *   **Use system proxy settings**
    *   **Trust any certificate (not secure)**  
    *   **Timeout (in seconds) for HTTP requests to Exchange Server**
    *   **Use a self deployed Azure Application**
4.  Click **Test** to validate the URLs, token, and connection.

## Authentication
For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).

### Required Permissions for self deployed Azure Applications
#### Office 365 Exchange Online
**full_access_as_app** - To set this permission follow [the Microsoft documentation](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth#configure-for-app-only-authentication).
You can't manage the **Office 365 Exchange Online** app permissions via the Azure portal.

## Fetched Incidents Data

The integration imports email messages from the destination folder in the target mailbox as incidents. If the message contains any attachments, they are uploaded to the War Room as files. If the attachment is an email, Demisto fetches information about the attached email and downloads all of its attachments (if there are any) as files.

To use Fetch incidents, configure a new instance and select the `Fetches incidents` option in the instance settings.

IMPORTANT: The initial fetch interval is the previous 10 minutes. If no emails were fetched before from the destination folder- all emails from 10 minutes prior to the instance configuration and up to the current time will be fetched.

Pay special attention to the following fields in the instance settings:

`Email Address` – mailbox to fetch incidents from.  
`Name of the folder from which to fetch incidents` – use this field to configure the destination folder from where emails should be fetched. The default is Inbox folder. Please note, if Exchange is configured with an international flavor `Inbox` will be named according to the configured language.

## Commands

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1.  Get the attachments of an item: ews-get-attachment
2.  Delete the attachments of an item: ews-delete-attachment
3.  Get a list of searchable mailboxes: ews-get-searchable-mailboxes
4.  Move an item to a different folder: ews-move-item
5.  Delete an item from a mailbox: ews-delete-items
6.  Search a single mailbox: ews-search-mailbox
7.  Get the contacts for a mailbox: ews-get-contacts
8.  Get the out-of-office status for a mailbox: ews-get-out-of-office
9.  Recover soft-deleted messages: ews-recover-messages
10.  Create a folder: ews-create-folder
11.  Mark an item as junk: ews-mark-item-as-junk
12.  Search for folders: ews-find-folders
13.  Get items of a folder: ews-get-items-from-folder
14.  Get items: ews-get-items
15.  Move an item to a different mailbox: ews-move-item-between-mailboxes
16.  Get a folder: ews-get-folder
17.  Expand a distribution list: ews-expand-group
18.  Mark items as read: ews-mark-items-as-read
19.  Send an email: send-mail

### 1\. Get the attachments of an item

* * *

Retrieves the actual attachments from an item (email message). To get all attachments for a message, only specify the item-id argument.

##### Required Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-get-attachment`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id|The ID of the email message for which to get the attachments.|Required|
|target-mailbox|The mailbox in which this attachment was found. If empty, the default mailbox is used. Otherwise, the user might require impersonation rights to this mailbox.|Optional|
|attachment-ids|The attachments ids to get. If none - all attachments will be retrieved from the message. Support multiple attachments with comma-separated value or array.|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.FileAttachments.attachmentId|string|The attachment ID. Used for file attachments only.|
|EWS.Items.FileAttachments.attachmentName|string|The attachment name. Used for file attachments only.|
|EWS.Items.FileAttachments.attachmentSHA256|string|The SHA256 hash of the attached file.|
|EWS.Items.FileAttachments.attachmentLastModifiedTime|date|The attachment last modified time. Used for file attachments only.|
|EWS.Items.ItemAttachments.datetimeCreated|date|The created time of the attached email.|
|EWS.Items.ItemAttachments.datetimeReceived|date|The received time of the attached email.|
|EWS.Items.ItemAttachments.datetimeSent|date|The sent time of the attached email.|
|EWS.Items.ItemAttachments.receivedBy|string|The received by address of the attached email.|
|EWS.Items.ItemAttachments.subject|string|The subject of the attached email.|
|EWS.Items.ItemAttachments.textBody|string|The body of the attached email (as text).|
|EWS.Items.ItemAttachments.headers|Unknown|The headers of the attached email.|
|EWS.Items.ItemAttachments.hasAttachments|boolean|Whether the attached email has attachments.|
|EWS.Items.ItemAttachments.itemId|string|The attached email item ID.|
|EWS.Items.ItemAttachments.toRecipients|Unknown|A list of recipient email addresses for the attached email.|
|EWS.Items.ItemAttachments.body|string|The body of the attached email (as HTML).|
|EWS.Items.ItemAttachments.attachmentSHA256|string|SHA256 hash of the attached email (as EML file).|
|EWS.Items.ItemAttachments.FileAttachments.attachmentSHA256|string|SHA256 hash of the attached files inside of the attached email.|
|EWS.Items.ItemAttachments.ItemAttachments.attachmentSHA256|string|SHA256 hash of the attached emails inside of the attached email.|
|EWS.Items.ItemAttachments.isRead|String|The read status of the attachment.|


##### Command Example

```
!ews-get-attachment item-id=BBFDShfdafFSDF3FADR3434DFASDFADAFDADFADFCJebinpkUAAAfxuiVAAA= target-mailbox=test@demistodev.onmicrosoft.com
```

##### Context Example

```
{
    "EWS": {
        "Items": {
            "ItemAttachments": {
                "originalItemId": "BBFDShfdafFSDF3FADR3434DFASDFADAFDADFADFCJebinpkUAAAfxuiVAAA=", 
                "attachmentSize": 2956, 
                "receivedBy": "test@demistodev.onmicrosoft.com", 
                "size": 28852, 
                "author": "test2@demistodev.onmicrosoft.com", 
                "attachmentLastModifiedTime": "2019-08-11T15:01:30+00:00", 
                "subject": "Moving Email between mailboxes", 
                "body": "Some text inside", 
                "datetimeCreated": "2019-08-11T15:01:47Z", 
                "importance": "Normal", 
                "attachmentType": "ItemAttachment", 
                "toRecipients": [
                    "test@demistodev.onmicrosoft.com"
                ], 
                "mailbox": "test@demistodev.onmicrosoft.com", 
                "isRead": false, 
                "attachmentIsInline": false, 
                "datetimeSent": "2019-08-07T12:50:19Z", 
                "lastModifiedTime": "2019-08-11T15:01:30Z", 
                "sender": "test2@demistodev.onmicrosoft.com", 
                "attachmentName": "Moving Email between mailboxes", 
                "datetimeReceived": "2019-08-07T12:50:20Z", 
                "attachmentSHA256": "119e27b28dc81bdfd4f498d44bd7a6d553a74ee03bdc83e6255a53", 
                "hasAttachments": false, 
                "headers": [
                    {
                        "name": "Subject", 
                        "value": "Moving Email between mailboxes"
                    }
		...
                ], 
                "attachmentId": "BBFDShfdafFSDF3FADR3434DFASDFADAFDADFADFCJebinpkUAAAfxuiVAAABEgAQAOpEfpzDB4dFkZ+/K4XSj44=", 
                "messageId": "message_id"
            }
        }
    }

```

### 2\. Delete the attachments of an item

* * *

Deletes the attachments of an item (email message).

##### Required Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-delete-attachment`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id|The ID of the email message for which to delete attachments.|Required|
|target-mailbox|The mailbox in which this attachment was found. If empty, the default mailbox is used. Otherwise, the user might require impersonation rights to this mailbox.|Optional|
|attachment-ids|A CSV list (or array) of attachment IDs to delete. If empty, all attachments will be deleted from the message.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.FileAttachments.attachmentId|string|The ID of the deleted attachment, in case of file attachment.|
|EWS.Items.ItemAttachments.attachmentId|string|The ID of the deleted attachment, in case of other attachment (for example, "email").|
|EWS.Items.FileAttachments.action|string|The deletion action in case of file attachment. This is a constant value: 'deleted'.|
|EWS.Items.ItemAttachments.action|string|The deletion action in case of other attachment (for example, "email"). This is a constant value: 'deleted'.|

##### Command Example

```
!ews-delete-attachment item-id=AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAA= target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

|action|attachmentId|
|--- |--- |
|deleted|AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAABEgAQAIUht2vrOdErec33=|

### Context Example

```
{
    "EWS": {
        "Items": {
            "FileAttachments": {
                "action": "deleted",
                "attachmentId": "AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAABEgAQAIUht2vrOdErec33="
            }
        }
    }
}

```

### 3\. Get a list of searchable mailboxes

* * *

Returns a list of searchable mailboxes.

##### Required Permissions

Requires eDiscovery permissions to the Exchange Server. For more information see the [Microsoft documentation](https://technet.microsoft.com/en-us/library/dd298059(v=exchg.160).aspx).

##### Base Command

`ews-get-searchable-mailboxes`

##### Input

There are no input arguments for this command.

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Mailboxes.mailbox|string|Addresses of the searchable mailboxes.|
|EWS.Mailboxes.mailboxId|string|IDs of the searchable mailboxes.|
|EWS.Mailboxes.displayName|string|The email display name.|
|EWS.Mailboxes.isExternal|boolean|Whether the mailbox is external.|
|EWS.Mailboxes.externalEmailAddress|string|The external email address.|

##### Command Example

```
!ews-get-searchable-mailboxes
```

##### Human Readable Output

|displayName|isExternal|mailbox|mailboxId|
|--- |--- |--- |--- |
|test|false|test@demistodev.onmicrosoft.com|/o=Exchange***/ou=Exchange Administrative Group ()/cn=**/cn=**-**|

##### Context Example

```
{
    "EWS": {
        "Mailboxes": [
            {
                "mailbox": "test@demistodev.onmicrosoft.com", 
                "displayName": "test", 
                "mailboxId": "/o=Exchange***/ou=Exchange Administrative Group ()/cn=**/cn=**-**", 
                "isExternal": "false"
            }
            ...
        ]
    }
}

```

### 4\. Move an item to a different folder

* * *

Move an item to a different folder in the mailbox.

##### Required Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-move-item`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id|The ID of the item to move.|Required|
|target-folder-path|The path to the folder to which to move the item. Complex paths are supported, for example, "Inbox\Phishing".|Required|
|target-mailbox|The mailbox on which to run the command.|Optional|
|is-public|Whether the target folder is a public folder.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.newItemID|string|The item ID after the move.|
|EWS.Items.messageID|string|The item message ID.|
|EWS.Items.itemId|string|The original item ID.|
|EWS.Items.action|string|The action taken. The value will be "moved".|

##### Command Example

```
!ews-move-item item-id=VDAFNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU34cSCSSSfBJebinpkUAAAAAAEMAACyyVyFtlsUQZfBJebinpkUAAAfxuiRAAA= target-folder-path=Moving target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

|action|itemId|messageId|newItemId|
|--- |--- |--- |--- |
|moved|VDAFNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU34cSCSSSfBJebinpkUAAAAAAEMAACyyVyFtlsUQZfBJebinpkUAAAfxuiRAAA||AAVAAAVN2NkLThmZjdmNTZjNTMxFFFFJTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVfafainpkUAAAfxxd+AAA=|

##### Context Example

    {
        "EWS": {
            "Items": {
                "action": "moved", 
                "itemId": "VDAFNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU34cSCSSSfBJebinpkUAAAAAAEMAACyyVyFtlsUQZfBJebinpkUAAAfxuiRAAA", 
                "newItemId": "AAVAAAVN2NkLThmZjdmNTZjNTMxFFFFJTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVfafainpkUAAAfxxd+AAA=", 
                "messageId": "<message_id>"
            }
        }
    }

### 5\. Delete an item from a mailbox

* * *

Delete items from mailbox.

##### Required Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-delete-items`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-ids|The item IDs to delete.|Required|
|delete-type|Deletion type. Can be "trash", "soft", or "hard".|Required|
|target-mailbox|The mailbox on which to run the command.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.itemId|string|The deleted item ID.|
|EWS.Items.messageId|string|The deleted message ID.|
|EWS.Items.action|string|The deletion action. Can be 'trash-deleted', 'soft-deleted', or 'hard-deleted'.|

##### Command Example

```
!ews-delete-items item-ids=VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA= delete-type=soft target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

|action|itemId|messageId|
|--- |--- |--- |
|soft-deleted|VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA=||

##### Context Example

```
{
    "EWS": {
        "Items": {
            "action": "soft-deleted", 
            "itemId": "VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA=", 
            "messageId": "messaage_id"
        }
    }
}

```

### 6\. Search a single mailbox

* * *

Searches for items in the specified mailbox. Specific permissions are needed for this operation to search in a target mailbox other than the default.

##### Required Permissions

Impersonation rights required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-search-mailbox`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|query|The search query string. For more information about the query syntax, see the [Microsoft documentation](https://msdn.microsoft.com/en-us/library/ee693615.aspx).|Optional|
|folder-path|The folder path in which to search. If empty, searches all the folders in the mailbox.|Optional|
|limit|Maximum number of results to return.|Optional|
|target-mailbox|The mailbox on which to apply the search.|Optional|
|is-public|Whether the folder is a Public Folder?|Optional|
|message-id|The message ID of the email. This will be ignored if a query argument is provided.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.itemId|string|The email item ID.|
|EWS.Items.hasAttachments|boolean|Whether the email has attachments.|
|EWS.Items.datetimeReceived|date|Received time of the email.|
|EWS.Items.datetimeSent|date|Sent time of the email.|
|EWS.Items.headers|Unknown|Email headers (list).|
|EWS.Items.sender|string|Sender email address of the email.|
|EWS.Items.subject|string|Subject of the email.|
|EWS.Items.textBody|string|Body of the email (as text).|
|EWS.Items.size|number|Email size.|
|EWS.Items.toRecipients|Unknown|List of email recipients addresses.|
|EWS.Items.receivedBy|Unknown|Email received by address.|
|EWS.Items.messageId|string|Email message ID.|
|EWS.Items.body|string|Body of the email (as HTML).|
|EWS.Items.FileAttachments.attachmentId|unknown|Attachment ID of the file attachment.|
|EWS.Items.ItemAttachments.attachmentId|unknown|Attachment ID of the item attachment.|
|EWS.Items.FileAttachments.attachmentName|unknown|Attachment name of the file attachment.|
|EWS.Items.ItemAttachments.attachmentName|unknown|Attachment name of the item attachment.|
|EWS.Items.isRead|String|The read status of the email.|

##### Command Example

```
!ews-search-mailbox query="subject:"Get Attachment Email" target-mailbox=test@demistodev.onmicrosoft.com limit=1
```

##### Human Readable Output

|sender|subject|hasAttachments|datetimeReceived|receivedBy|author|toRecipients|
|--- |--- |--- |--- |--- |--- |--- |
|test2@demistodev.onmicrosoft.com|Get Attachment Email|true|2019-08-11T10:57:37Z|test@demistodev.onmicrosoft.com|test2@demistodev.onmicrosoft.com|test@demistodev.onmicrosoft.com|

##### Context Example

```
{
    "EWS": {
        "Items": {
            "body": "<html>\r\n<head>\r\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\r\n<style type=\"text/css\" style=\"display:none;\"><!-- P {margin-top:0;margin-bottom:0;} --></style>\r\n</head>\r\n<body dir=\"ltr\">\r\n<div id=\"divtagrapper\" style=\"font-size:12pt;color:#000000;font-family:Calibri,Helvetica,sans-serif;\" dir=\"ltr\">\r\n<p style=\"margin-top:0;margin-bottom:0\">Some text inside email</p>\r\n</div>\r\n</body>\r\n</html>\r\n", 
            "itemId": "AAMkADQ0NmFFijer3FFmNTZjNTMxNwBGAAAAAAFSAAfxw+jAAA=", 
            "toRecipients": [
                "test@demistodev.onmicrosoft.com"
            ], 
            "datetimeCreated": "2019-08-11T10:57:37Z", 
            "datetimeReceived": "2019-08-11T10:57:37Z", 
            "author": "test2@demistodev.onmicrosoft.com", 
            "hasAttachments": true, 
            "size": 30455, 
            "subject": "Get Attachment Email", 
            "FileAttachments": [
                {
                    "attachmentName": "atta1.rtf", 
                    "attachmentSHA256": "csfd81097bc049fbcff6e637ade0407a00308bfdfa339e31a44a1c4e98f28ce36e4f", 
                    "attachmentType": "FileAttachment", 
                    "attachmentSize": 555, 
                    "attachmentId": "AAMkADQ0NmFkODFkLWQ4MDEtNDE4Mi1hN2NkLThmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAfxw+jAAABEgAQAEyq1TB2nKBLpKUiFUJ5Geg=", 
                    "attachmentIsInline": false, 
                    "attachmentLastModifiedTime": "2019-08-11T11:06:02+00:00", 
                    "attachmentContentLocation": null, 
                    "attachmentContentType": "text/rtf", 
                    "originalItemId": "AAMkADQ0NmFFijer3FFmNTZjNTMxNwBGAAAAAAFSAAfxw+jAAA=", 
                    "attachmentContentId": null
                }
            ], 
            "headers": [
                {
                    "name": "Subject", 
                    "value": "Get Attachment Email"
                }, 
                ...
            ], 
            "isRead": true, 
            "messageId": "<mesage_id>", 
            "receivedBy": "test@demistodev.onmicrosoft.com", 
            "datetimeSent": "2019-08-11T10:57:36Z", 
            "lastModifiedTime": "2019-08-11T11:13:59Z", 
            "mailbox": "test@demistodev.onmicrosoft.com", 
            "importance": "Normal", 
            "textBody": "Some text inside email\r\n", 
            "sender": "test2@demistodev.onmicrosoft.com"
        }
    }
}

```

### 7\. Get the contacts for a mailbox

* * *

Retrieves contacts for a specified mailbox.

##### Required Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-get-contacts`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|target-mailbox|The mailbox for which to retrieve the contacts.|Optional|
|limit|Maximum number of results to return.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|Account.Email.EwsContacts.displayName|Unknown|The contact name.|
|Account.Email.EwsContacts.lastModifiedTime|Unknown|The time that the contact was last modified.|
|Account.Email.EwsContacts.emailAddresses|Unknown|Phone numbers of the contact.|
|Account.Email.EwsContacts.physicalAddresses|Unknown|Physical addresses of the contact.|
|Account.Email.EwsContacts.phoneNumbers.phoneNumber|Unknown|Email addresses of the contact.|

##### Command Example

```
!ews-get-contacts limit="1"
```

##### Human Readable Output

|changekey|culture|datetimeCreated|datetimeReceived|datetimeSent|displayName|emailAddresses|fileAs|fileAsMapping|givenName|id|importance|itemClass|lastModifiedName|lastModifiedTime|postalAddressIndex|sensitivity|subject|uniqueBody|webClientReadFormQueryString|
|--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |
|EABYACAADcsxRwRjq/zTrN6vWSzKAK1Dl3N|en-US|2019-08-05T12:35:36Z|2019-08-05T12:35:36Z|2019-08-05T12:35:36Z|Contact Name|some@dev.microsoft.com|Contact Name|LastCommaFirst|Contact Name|AHSNNK3NQNcasnc3SAS/zTrN6vWSzK4OWAAAAAAEOAADrxRwRjq/zTrNFSsfsfVWAAK1KsF3AAA=|Normal|IPM.Contact|John Smith|2019-08-05T12:35:36Z|None|Normal|Contact Name||https://outlook.office365.com/owa/?ItemID=***|

##### Context Example

```
{
    "Account.Email": [
        {
            "itemClass": "IPM.Contact", 
            "lastModifiedName": "John Smith", 
            "displayName": "Contact Name", 
            "datetimeCreated": "2019-08-05T12:35:36Z", 
            "datetimeReceived": "2019-08-05T12:35:36Z", 
            "fileAsMapping": "LastCommaFirst", 
            "importance": "Normal", 
            "sensitivity": "Normal", 
            "postalAddressIndex": "None", 
            "webClientReadFormQueryString": "https://outlook.office365.com/owa/?ItemID=***", 
            "uniqueBody": "<html><body></body></html>", 
            "fileAs": "Contact Name", 
            "culture": "en-US", 
            "changekey": "EABYACAADcsxRwRjq/zTrN6vWSzKAK1Dl3N", 
            "lastModifiedTime": "2019-08-05T12:35:36Z", 
            "datetimeSent": "2019-08-05T12:35:36Z", 
            "emailAddresses": [
                "some@dev.microsoft.com"
            ], 
            "givenName": "Contact Name", 
            "id": "AHSNNK3NQNcasnc3SAS/zTrN6vWSzK4OWAAAAAAEOAADrxRwRjq/zTrNFSsfsfVWAAK1KsF3AAA=", 
            "subject": "Contact Name"
        }
    ]
}

```

### 8\. Get the out-of-office status for a mailbox

* * *

Retrieves the out-of-office status for a specified mailbox.

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part the ApplicationImpersonation role.

##### Base Command

`ews-get-out-of-office`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|target-mailbox|The mailbox for which to get the out-of-office status.|Required|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|Account.Email.OutOfOffice.state|Unknown|Out-of-office state. The result can be: "Enabled", "Scheduled", or "Disabled".|
|Account.Email.OutOfOffice.externalAudience|Unknown|Out-of-office external audience. Can be "None", "Known", or "All".|
|Account.Email.OutOfOffice.start|Unknown|Out-of-office start date.|
|Account.Email.OutOfOffice.end|Unknown|Out-of-office end date.|
|Account.Email.OutOfOffice.internalReply|Unknown|Out-of-office internal reply.|
|Account.Email.OutOfOffice.externalReply|Unknown|Out-of-office external reply.|
|Account.Email.OutOfOffice.mailbox|Unknown|Out-of-office mailbox.|

##### Command Example

```
!ews-get-out-of-office target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

|end|externalAudience|mailbox|start|state|
|--- |--- |--- |--- |--- |
|2019-08-12T13:00:00Z|All|test@demistodev.onmicrosoft.com|2019-08-11T13:00:00Z|Disabled|

##### Context Example

```
{
    "Account": {
        "Email": {
            "OutOfOffice": {
                "start": "2019-08-11T13:00:00Z", 
                "state": "Disabled", 
                "mailbox": "test@demistodev.onmicrosoft.com", 
                "end": "2019-08-12T13:00:00Z", 
                "externalAudience": "All"
            }
        }
    }
}

```

### 9\. Recover soft-deleted messages

* * *

Recovers messages that were soft-deleted.

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-recover-messages`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|message-ids|A CSV list of message IDs. Run the py-ews-delete-items command to retrieve the message IDs|Required|
|target-folder-path|The folder path to recover the messages to.|Required|
|target-mailbox|The mailbox in which the messages found. If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox.|Optional|
|is-public|Whether the target folder is a Public Folder.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.itemId|Unknown|The item ID of the recovered item.|
|EWS.Items.messageId|Unknown|The message ID of the recovered item.|
|EWS.Items.action|Unknown|The action taken on the item. The value will be 'recovered'.|

##### Command Example

```
!ews-recover-messages message-ids=<DFVDFmvsCSCS.com> target-folder-path=Moving target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

|action|itemId|messageId|
|--- |--- |--- |
|recovered|AAVCSVS1hN2NkLThmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed33wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVyFtlscfxxd/AAA=||

##### Context Example

```
{
    "EWS": {
        "Items": {
            "action": "recovered", 
            "itemId": "AAVCSVS1hN2NkLThmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed33wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVyFtlscfxxd/AAA=", 
            "messageId": "<DFVDFmvsCSCS.com>"
        }
    }
}

```

### 10\. Create a folder

* * *

Creates a new folder in a specified mailbox.

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-create-folder`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|new-folder-name|The name of the new folder.|Required|
|folder-path|Path to locate the new folder. Exchange folder ID is also supported.|Required|
|target-mailbox|The mailbox in which to create the folder.|Optional|

##### Context Output

There is no context output for this command.

##### Command Example

```
!ews-create-folder folder-path=Inbox new-folder-name="Created Folder" target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

Folder Inbox\Created Folder created successfully

### 11\. Mark an item as junk

* * *

Marks an item as junk. This is commonly used to block an email address. For more information, see the [Microsoft documentation](https://msdn.microsoft.com/en-us/library/office/dn481311(v=exchg.150).aspx). 

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-mark-item-as-junk`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id|The item ID to mark as junk.|Required|
|move-items|Whether to move the item from the original folder to the junk folder.|Optional|
|target-mailbox|If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox.|Optional|

##### Context Output

There is no context output for this command.

##### Command Example

```
!ews-mark-item-as-junk item-id=AAMkcSQ0NmFkOhmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUcsBJebinpkUAAAAAAEMASFDkUAAAfxuiSAAA= move-items=yes target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

|action|itemId|
|--- |--- |
|marked-as-junk|AAMkcSQ0NmFkOhmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUcsBJebinpkUAAAAAAEMASFDkUAAAfxuiSAAA=|

##### Context Example

```
{
    "EWS": {
        "Items": {
            "action": "marked-as-junk", 
            "itemId": "AAMkcSQ0NmFkOhmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUcsBJebinpkUAAAAAAEMASFDkUAAAfxuiSAAA="
        }
    }
}

```

### 12\. Search for folders

* * *

Retrieves information for the folders of the specified mailbox. Only folders with read permissions will be returned. Your visual folders on the mailbox, such as "Inbox", are under the folder "Top of Information Store".

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-find-folders`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|target-mailbox|The mailbox on which to apply the command.|Optional|
|is-public|Whether to find Public Folders.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Folders.name|string|Folder name.|
|EWS.Folders.id|string|Folder ID.|
|EWS.Folders.totalCount|Unknown|Number of items in the folder.|
|EWS.Folders.unreadCount|number|Number of unread items in the folder.|
|EWS.Folders.changeKey|number|Folder change key.|
|EWS.Folders.childrenFolderCount|number|Number of sub-folders.|

##### Command Example

```
!ews-find-folders target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

```
root
├── AllContacts
├── AllItems
├── Common Views
├── Deferred Action
├── ExchangeSyncData
├── Favorites
├── Freebusy Data
├── Location
├── MailboxAssociations
├── My Contacts
├── MyContactsExtended
├── People I Know
├── PeopleConnect
├── Recoverable Items
│ ├── Calendar Logging
│ ├── Deletions
│ ── Purges
│ └── Versions
├── Reminders
├── Schedule
├── Sharing
├── Shortcuts
├── Spooler Queue
├── System
├── To-Do Search
├── Top of Information Store
│ ├── Calendar
│ ├── Contacts
│ │ ├── GAL Contacts
│ │ ├── Recipient Cache
│ ├── Conversation Action Settings
│ ├── Deleted Items
│ │ └── Create1
│ ├── Drafts
│ ├── Inbox
...

```

##### Context Example

```
{
    "EWS": {
        "Folders": [    
            {
                "unreadCount": 1, 
                "name": "Inbox", 
                "childrenFolderCount": 1, 
                "totalCount": 44, 
                "changeKey": "**********fefsduQi0", 
                "id": "*******VyFtlFDSAFDSFDAAA="
            }
            ...
        ]
    }
}

```

### 13\. Get items of a folder

* * *

Retrieves items from a specified folder in a mailbox. The items are ordered by the item created time, most recent is first.

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-get-items-from-folder`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|folder-path|The folder path from which to get the items.|Required|
|limit|Maximum number of items to return.|Optional|
|target-mailbox|The mailbox on which to apply the command.|Optional|
|is-public|Whether the folder is a Public Folder. Default is 'False'.|Optional|
|get-internal-items|If the email item contains another email as an attachment (EML or MSG file), whether to retrieve the EML/MSG file attachment. Can be "yes" or "no". Default is "no".|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.itemId|string|The item ID of the email.|
|EWS.Items.hasAttachments|boolean|Whether the email has attachments.|
|EWS.Items.datetimeReceived|date|Received time of the email.|
|EWS.Items.datetimeSent|date|Sent time of the email.|
|EWS.Items.headers|Unknown|Email headers (list).|
|EWS.Items.sender|string|Sender mail address of the email.|
|EWS.Items.subject|string|Subject of the email.|
|EWS.Items.textBody|string|Body of the email (as text).|
|EWS.Items.size|number|Email size.|
|EWS.Items.toRecipients|Unknown|Email recipients addresses (list).|
|EWS.Items.receivedBy|Unknown|Received by address of the email.|
|EWS.Items.messageId|string|Email message ID.|
|EWS.Items.body|string|Body of the email (as HTML).|
|EWS.Items.FileAttachments.attachmentId|unknown|Attachment ID of file attachment.|
|EWS.Items.ItemAttachments.attachmentId|unknown|Attachment ID of the item attachment.|
|EWS.Items.FileAttachments.attachmentName|unknown|Attachment name of the file attachment.|
|EWS.Items.ItemAttachments.attachmentName|unknown|Attachment name of the item attachment.|
|Email.Items.ItemAttachments.attachmentName|unknown|Attachment name of the item attachment.|
|EWS.Items.isRead|String|The read status of the email.|

##### Command Example

```
!ews-get-items-from-folder folder-path=Test target-mailbox=test@demistodev.onmicrosoft.com limit=1
```

##### Human Readable Output

|sender|subject|hasAttachments|datetimeReceived|receivedBy|author|toRecipients|itemId|
|--- |--- |--- |--- |--- |--- |--- |--- |
|test2@demistodev.onmicrosoft.com|Get Attachment Email|true|2019-08-11T10:57:37Z|test@demistodev.onmicrosoft.com|test2@demistodev.onmicrosoft.com|test@demistodev.onmicrosoft.com|AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAA=|

##### Context Example

```
{
    "EWS": {
        "Items": {
            "body": "<html>\r\n<head>\r\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\r\n<style type=\"text/css\" style=\"display:none;\"><!-- P {margin-top:0;margin-bottom:0;} --></style>\r\n</head>\r\n<body dir=\"ltr\">\r\n<div id=\"divtagdefaultwrapper\" style=\"font-size:12pt;color:#000000;font-family:Calibri,Helvetica,sans-serif;\" dir=\"ltr\">\r\n<p style=\"margin-top:0;margin-bottom:0\">Some text inside email</p>\r\n</div>\r\n</body>\r\n</html>\r\n", 
            "itemId": "AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAA=", 
            "toRecipients": [
                "test@demistodev.onmicrosoft.com"
            ], 
            "datetimeCreated": "2019-08-11T10:57:37Z", 
            "datetimeReceived": "2019-08-11T10:57:37Z", 
            "author": "test2@demistodev.onmicrosoft.com", 
            "hasAttachments": true, 
            "size": 21435, 
            "subject": "Get Attachment Email", 
            "FileAttachments": [
                {
                    "attachmentName": "atta1.rtf", 
                    "attachmentSHA256": "cd81097bcvdiojf3407a00308b48039e31a44a1c4fdnfkdknce36e4f", 
                    "attachmentType": "FileAttachment", 
                    "attachmentSize": 535, 
                    "attachmentId": "AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAABEgAQAEyq1TB2nKBLpKUiFUJ5Geg=", 
                    "attachmentIsInline": false, 
                    "attachmentLastModifiedTime": "2019-08-11T11:06:02+00:00", 
                    "attachmentContentLocation": null, 
                    "attachmentContentType": "text/rtf", 
                    "originalItemId": "AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAA=", 
                    "attachmentContentId": null
                }
            ], 
            "headers": [
                {
                    "name": "Subject", 
                    "value": "Get Attachment Email"
                },
                ...
                            ], 
            "isRead": true, 
            "messageId": "<message_id>", 
            "receivedBy": "test@demistodev.onmicrosoft.com", 
            "datetimeSent": "2019-08-11T10:57:36Z", 
            "lastModifiedTime": "2019-08-11T11:13:59Z", 
            "mailbox": "test@demistodev.onmicrosoft.com", 
            "importance": "Normal", 
            "textBody": "Some text inside email\r\n", 
            "sender": "test2@demistodev.onmicrosoft.com"
        }
    }
}

```

### 14\. Get items

* * *

Retrieves items by item ID.

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-get-items`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-ids|A CSV list of item IDs.|Required|
|target-mailbox|The mailbox on which to run the command on.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.itemId|string|The email item ID.|
|EWS.Items.hasAttachments|boolean|Whether the email has attachments.|
|EWS.Items.datetimeReceived|date|Received time of the email.|
|EWS.Items.datetimeSent|date|Sent time of the email.|
|EWS.Items.headers|Unknown|Email headers (list).|
|EWS.Items.sender|string|Sender mail address of the email.|
|EWS.Items.subject|string|Subject of the email.|
|EWS.Items.textBody|string|Body of the email (as text).|
|EWS.Items.size|number|Email size.|
|EWS.Items.toRecipients|Unknown|Email recipients addresses (list).|
|EWS.Items.receivedBy|Unknown|Received by address of the email.|
|EWS.Items.messageId|string|Email message ID.|
|EWS.Items.body|string|Body of the email (as HTML).|
|EWS.Items.FileAttachments.attachmentId|unknown|Attachment ID of the file attachment.|
|EWS.Items.ItemAttachments.attachmentId|unknown|Attachment ID of the item attachment.|
|EWS.Items.FileAttachments.attachmentName|unknown|Attachment name of the file attachment.|
|EWS.Items.ItemAttachments.attachmentName|unknown|Attachment name of the item attachment.|
|EWS.Items.isRead|String|The read status of the email.|
|Email.CC|String|Email addresses CC'ed to the email.|
|Email.BCC|String|Email addresses BCC'ed to the email.|
|Email.To|String|The recipient of the email.|
|Email.From|String|The sender of the email.|
|Email.Subject|String|The subject of the email.|
|Email.Text|String|The plain-text version of the email.|
|Email.HTML|String|The HTML version of the email.|
|Email.HeadersMap|String|The headers of the email.|

##### Command Example

```
!ews-get-items item-ids=AAMkADQ0NmFkODFkLWQ4MDEtNDFDFZjNTMxNwBGAAAAAAA4kxhFFAfxw+jAAA= target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

Identical outputs to `ews-get-items-from-folder` command.

### 15\. Move an item to a different mailbox

* * *

Moves an item from one mailbox to a different mailbox.

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-move-item-between-mailboxes`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id|The item ID to move.|Required|
|destination-folder-path|The folder in the destination mailbox to which to move the item. You can specify a complex path, for example, "Inbox\Phishing".|Required|
|destination-mailbox|The mailbox to which to move the item.|Required|
|source-mailbox|The mailbox from which to move the item (conventionally called the "target-mailbox", the target mailbox on which to run the command).|Optional|
|is-public|Whether the destination folder is a Public Folder. Default is "False".|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.movedToMailbox|string|The mailbox to which the item was moved.|
|EWS.Items.movedToFolder|string|The folder to which the item was moved.|
|EWS.Items.action|string|The action taken on the item. The value will be "moved".|

##### Command Example

```
!ews-move-item-between-mailboxes item-id=AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NFSFSyNzBkNABGAAAAAACYCKjWAjq/zTrN6vWSzK4OWAAK2ISFSA= destination-folder-path=Moving destination-mailbox=test@demistodev.onmicrosoft.com source-mailbox=test2@demistodev.onmicrosoft.com
```

##### Human Readable Output

Item was moved successfully.

##### Context Example

```
{
    "EWS": {
        "Items": {
            "movedToMailbox": "test@demistodev.onmicrosoft.com", 
            "movedToFolder": "Moving"
        }
    }
}

```

### 16\. Get a folder

* * *

Retrieves a single folder.

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-get-folder`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|target-mailbox|The mailbox on which to apply the search.|Optional|
|folder-path|The path of the folder to retrieve. If empty, will retrieve the folder "AllItems".|Optional|
|is-public|Whether the folder is a Public Folder. Default is "False".|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Folders.id|string|Folder ID.|
|EWS.Folders.name|string|Folder name.|
|EWS.Folders.changeKey|string|Folder change key.|
|EWS.Folders.totalCount|number|Total number of emails in the folder.|
|EWS.Folders.childrenFolderCount|number|Number of sub-folders.|
|EWS.Folders.unreadCount|number|Number of unread emails in the folder.|

##### Command Example

```
!ews-get-folder folder-path=demistoEmail target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

|changeKey|childrenFolderCount|id|name|totalCount|unreadCount|
|--- |--- |--- |--- |--- |--- |
|***yFtCdJSH|0|AAMkADQ0NmFkODFkLWQ4MDEtNDE4Mi1hN2NlsjflsjfSF=|demistoEmail|1|0|

##### Context Example

```
{
    "EWS": {
        "Folders": {
            "unreadCount": 0, 
            "name": "demistoEmail", 
            "childrenFolderCount": 0, 
            "totalCount": 1, 
            "changeKey": "***yFtCdJSH", 
            "id": "AAMkADQ0NmFkODFkLWQ4MDEtNDE4Mi1hN2NlsjflsjfSF="
        }
    }
}

```

### 17\. Expand a distribution list

* * *

Expands a distribution list to display all members. By default, expands only the first layer of the distribution list. If recursive-expansion is "True", the command expands nested distribution lists and returns all members.

##### Required Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-expand-group`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|email-address|Email address of the group to expand.|Required|
|recursive-expansion|Whether to enable recursive expansion. Default is "False".|Optional|

##### Context Output

There is no context output for this command.

##### Command Example

```
!ews-expand-group email-address="TestPublic" recursive-expansion="False"
```

##### Human Readable Output

|displayName|mailbox|mailboxType|
|--- |--- |--- |
|John Wick|john@wick.com|Mailbox|

##### Context Example

```
{
    "EWS.ExpandGroup": {
        "name": "TestPublic", 
        "members": [
            {
                "mailboxType": "Mailbox", 
                "displayName": "John Wick", 
                "mailbox": "john@wick.com"
            }
        ]
    }
}

```

### 18\. Mark items as read

* * *

Marks items as read or unread.

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`ews-mark-items-as-read`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-ids|A CSV list of item IDs.|Required|
|operation|How to mark the item. Can be "read" or "unread". Default is "read".|Optional|
|target-mailbox|The mailbox on which to run the command. If empty, the command will be applied on the default mailbox.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.action|String|The action that was performed on the item.|
|EWS.Items.itemId|String|The ID of the item.|
|EWS.Items.messageId|String|The message ID of the item.|

##### Command Example

```
!ews-mark-items-as-read item-ids=AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA= operation=read target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

|action|itemId|messageId|
|--- |--- |--- |
|marked-as-read|AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA=||

##### Context Example

```
{
    "EWS": {
        "Items": {
            "action": "marked-as-read", 
            "itemId": "AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA= ", 
            "messageId": "message_id"
        }
    }
}

```

### 19\. Send an email

* * *

##### Required Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.

##### Base Command

`send-mail`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Email addresses for the 'To' field. Supports comma-separated values | Optional | 
| cc | Email addresses for the 'Cc' field. Supports comma-separated values | Optional | 
| bcc | Email addresses for the 'Bcc' field. Supports comma-separated values | Optional | 
| subject | Subject for the email to be sent | Optional | 
| body | The contents (body) of the email to be sent in plain text | Optional | 
| htmlBody | The contents (body) of the email to be sent in HTML format | Optional | 
| attachIDs | A comma-separated list of IDs of war room entries that contains the files that should be attached to the email | Optional | 
| attachNames | A comma-separated list to rename file-names of corresponding attachments IDs. (e.g. rename first two files - attachNames=file_name1,file_name2. rename first and third file - attachNames=file_name1,,file_name3) | Optional | 
| attachCIDs | A comma-separated list of CIDs to embed attachments inside the email itself | Optional | 
| transientFile | Desired name for attached file. Multiple files are supported as comma-separated list. (e.g. transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz") | Optional | 
| transientFileContent | Content for attached file. Multiple files are supported as comma-separated list. (e.g. transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz") | Optional | 
| transientFileCID | CID for attached file if we want it inline. Multiple files are supported as comma-separated list. (e.g. transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz") | Optional | 
| templateParams | Replace {varname} variables with values from this argument. Expected values are in the form of a JSON document like {"varname": {"value": "some value", "key": "context key"}}. Each var name can either be provided with the value or a context key to retrieve the value from | Optional | 
| additionalHeader | A comma-separated list list of additional headers in the format: headerName=headerValue. For example: "headerName1=headerValue1,headerName2=headerValue2". | Optional | 
| raw_message | Raw email message to send. If provided, all other arguments, but to, cc and bcc, will be ignored. | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example

```
!send-mail to=demisto@demisto.onmicrosoft.com subject=some_subject body=some_text attachIDs=110@457,116@457 htmlBody="<html><body>Hello <b>World</b></body></html>" additionalHeader="some_header_name=some_header_value" transientFile=some_file.txt transientFileContent="Some file content"
```

##### Human Readable Output

Mail sent successfully

## Additional Information

* * *

#### EWS Permissions

To perform actions on mailboxes of other users, and to execute searches on the Exchange server, you need specific permissions. For a comparison between Delegate and Impersonation permissions, see the [Microsoft documentation](https://blogs.msdn.microsoft.com/exchangedev/2009/06/15/exchange-impersonation-vs-delegate-access/).

|Permission|Use Case|How to Configure|
|--- |--- |--- |
|Delegate|One-to-one relationship between users.|Read more [here](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/delegate-access-and-ews-in-exchange).|
|Impersonation|A single account needs to access multiple mailboxes.|Read more [here](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-configure-impersonation).|
|eDiscovery|Search the Exchange server.|Read more [here](https://docs.microsoft.com/en-us/Exchange/policy-and-compliance/ediscovery/assign-permissions?view=exchserver-2019).|
|Compliance Search|Perform searches across mailboxes and get an estimate of the results.|Read more [here](https://docs.microsoft.com/en-us/office365/securitycompliance/permissions-in-the-security-and-compliance-center).|
