Exchange Web Services (EWS) provides the functionality to enable client applications to communicate with the Exchange server. EWS provides access to much of the same data that is made available through Microsoft Office Outlook.

The EWS v2 integration implants EWS leading services. The integration allows getting information on emails and activities in a target mailbox, and some active operations on the mailbox such as deleting emails and attachments or moving emails from folder to folder.

**Note:** Starting from pack version 2.0.0 the EWS v2 integration requires the Exchange server to support TLS v1.2 and up in order to connect.

**Multi-Factor Authentication (MFA)**
EWS v2 does not support Multi-Factor Authentication (MFA).

If using MFA, use EWS O365 (see <https://xsoar.pan.dev/docs/reference/integrations/ewso365>) 

or if you have Graph Outlook use O365 Outlook Mail (Using Graph API) (see <https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph-mail>)

or O365 Outlook Mail Single User (Using Graph API) (see <https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph-mail-single-user>).

## EWS v2 Playbooks

- Office 365 Search and Delete
- Search And Delete Emails - EWS
- Get Original Email - EWS
- Process Email - EWS

## Use Cases

The EWS integration can be used for the following use cases:

- Monitor a specific email account and create incidents from incoming emails to the defined folder.
Follow the instructions in the [Fetched Incidents Data](#fetched-incidents-data) section.
- Search for an email message across mailboxes and folders.
  This can be achieved in the following ways:
  - Use the ```ews-search-mailboxes``` command to search for all emails in a specific scope of mailboxes. Use the filter argument to narrow the search for emails sent from a specific account and more.
  - Use the ```ews-search-mailbox``` command to search for all emails in a specific folder within the target mailbox. Use the query argument to narrow the search for emails sent from a specific account and more.
  
  Both of these commands retrieve the *ItemID* field for each email item listed in the results. The```ItemID``` can be used in the ```ews-get-items``` command in order to get more information about the email item itself.
  For instance, use the ```ews-search-mailboxes``` command to hunt for emails that were marked as malicious in prior investigations, across organization mailboxes. Focus your hunt on emails sent from a specific mail account, emails with a specific subject and more.

- Get email attachment information. Use the ```ews-get-attachment``` command to retrieve information on one attachment or all attachments of a message at once. It supports both file attachments and item attachments (e.g., email messages).
- Delete email items from a mailbox. First, make sure you obtain the email item ID. The item ID can be obtained with one of the integration’s search commands. Use the ```ews-delete-items``` command to delete one or more items from the target mailbox in a single action. A less common use case is to remove emails that were marked as malicious from a user’s mailbox. You can delete the items permanently (hard delete), or delete the items (soft delete), so they can be recovered by running the ```ews-recover-messages``` command.
- Send notifications to external users.
- Send an email asking for a response to be returned as part of a playbook. See [Receiving an email reply](https://xsoar.pan.dev/docs/reference/scripts/email-ask-user)

## Configure EWS v2 in Cortex


| **Parameter**                                                                                                                                 | **Required** |
|-----------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Email address                                                                                                                                 | True         |
| Password                                                                                                                                      | True         |
| Email address from which to fetch incidents                                                                                                   | True         |
| Name of the folder from which to fetch incidents (supports Exchange Folder ID and sub-folders e.g. Inbox/Phishing)                            | True         |
| Public Folder                                                                                                                                 | False        |
| Has impersonation rights                                                                                                                      | False        |
| Use system proxy settings                                                                                                                     | False        |
| Fetch incidents                                                                                                                               | False        |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days)                                                              | False        |
| Mark fetched emails as read                                                                                                                   | False        |
| Incident type                                                                                                                                 | False        |
| ┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉<br/>‎                                           Manual Mode<br/>Exchange Server Hostname or IP address                 | False        |
| DOMAIN\USERNAME (e.g. DEMISTO.INT\admin)                                                                                                      | False        |
| Exchange Server Version (On-Premise only. Supported versions: 2007, 2010, 2010_SP2, 2013, 2016, and 2019)                                     | False        |
| Trust any certificate (not secure)                                                                                                            | False        |
| ┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉<br/>‎                                         Advanced Mode<br/>Override Authentication Type (NTLM, Basic, or Digest). | False        |
| Timeout (in seconds) for HTTP requests to Exchange Server                                                                                     | False        |
| Max incidents per fetch                                                                                                                       | False        |
| Run as a separate process (protects against memory depletion)                                                                                 | False        |
| Skip unparsable emails during fetch incidents                                                                                                 | False        |



## Fetched Incidents Data

The integration imports email messages from the destination folder in the target mailbox as incidents. If the message contains any attachments, they are uploaded to the War Room as files. If the attachment is an email, Cortex XSOAR fetches information about the attached email and downloads all of its attachments (if there are any) as files.

To use Fetch incidents, configure a new instance and select the ```Fetches incidents``` option in the instance settings.

**IMPORTANT:** The initial fetch interval is the previous 10 minutes. If no emails were fetched before from the destination folder, all emails from 10 minutes prior to the instance configuration and up to the current time will be fetched. Additionally, moving messages manually to the destination folder will not trigger a fetch incident. Define rules on phishing/target mailbox instead of moving messages manually.

You can configure the ``First fetch timestamp`` field to determine how much time back you want to fetch incidents.

Notice that it might require you to set the ``Timeout`` field to a higher value.

Pay special attention to the following fields in the instance settings:

- ```Email address from which to fetch incidents``` – mailbox to fetch incidents from.

- ```Name of the folder from which to fetch incidents``` – use this field to configure the destination folder from where emails should be fetched. The default is Inbox folder. Please note, if Exchange is configured with an international flavor, `Inbox` will be named according to the configured language.

- ```Has impersonation rights``` – mark this option if you set the target mailbox to an account different than your personal account. Otherwise Delegation access will be used instead of Impersonation.
Find more information on impersonation or delegation rights in the  [Additional Information](#additional-information) section.


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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


#### Command Example

```!ews-get-attachment item-id=BBFDShfdafFSDF3FADR3434DFASDFADAFDADFADFCJebinpkUAAAfxuiVAAA= target-mailbox=test@demistodev.onmicrosoft.com```

#### Context Example

```json
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
        ],
        "attachmentId": "BBFDShfdafFSDF3FADR3434DFASDFADAFDADFADFCJebinpkUAAAfxuiVAAABEgAQAOpEfpzDB4dFkZ+/K4XSj44=",
        "messageId": "&lt;message_id&gt;"
      }
    }
  }
}
```

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
| attachment-ids | A CSV list (or array) of attachment IDs to delete. If empty, all attachments will be deleted from the message. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.FileAttachments.attachmentId | string | The ID of the deleted attachment, in case of file attachment. | 
| EWS.Items.ItemAttachments.attachmentId | string | The ID of the deleted attachment, in case of other attachment \(for example, "email"\). | 
| EWS.Items.FileAttachments.action | string | The deletion action in case of file attachment. This is a constant value: 'deleted'. | 
| EWS.Items.ItemAttachments.action | string | The deletion action in case of other attachment \(for example, "email"\). This is a constant value: 'deleted'. | 


#### Command Example

```!ews-delete-attachment item-id=AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAA= target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

>|action|attachmentId|
>|---|---|
>| deleted | AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAABEgAQAIUht2vrOdErec33= |

#### Context Example

```json
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

### ews-get-searchable-mailboxes

***
Returns a list of searchable mailboxes. This command requires eDiscovery permissions to the Exchange Server. For more information, see the EWSv2 integration documentation.


#### Base Command

`ews-get-searchable-mailboxes`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Mailboxes.mailbox | string | Addresses of the searchable mailboxes. | 
| EWS.Mailboxes.mailboxId | string | IDs of the searchable mailboxes. | 
| EWS.Mailboxes.displayName | string | The email display name. | 
| EWS.Mailboxes.isExternal | boolean | Whether the mailbox is external. | 
| EWS.Mailboxes.externalEmailAddress | string | The external email address. | 


#### Command Example

```!ews-get-searchable-mailboxes```

#### Human Readable Output

>|displayName|isExternal|mailbox|mailboxId|
>|---|---|---|--- |
>| test | false |test@demistodev.onmicrosoft.com | /o=Exchange***/ou=Exchange Administrative Group ()/cn=**/cn=**-**|

#### Context Example

```json
{
    "EWS": {
        "Mailboxes": [
            {
                "mailbox": "test@demistodev.onmicrosoft.com", 
                "displayName": "test", 
                "mailboxId": "/o=Exchange***/ou=Exchange Administrative Group ()/cn=**/cn=**-**", 
                "isExternal": "false"
            }
        ]
    }
}
```


### ews-search-mailboxes

***
Searches over multiple mailboxes or all Exchange mailboxes. Use either the mailbox-search-scope command or the email-addresses command to search specific mailboxes. This command requires eDiscovery permissions to the Exchange Server. For more information, see the EWS v2 integration documentation.

The number of mailboxes to search in may be limited by Microsoft Exchange. See [here](https://learn.microsoft.com/en-us/exchange/new-features/new-features?view=exchserver-2019#improved-performance-and-scalability) for more information. 

#### Base Command

`ews-search-mailboxes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The filter query to search. | Required | 
| mailbox-search-scope | The mailbox IDs to search. If empty, all mailboxes are searched. | Optional | 
| limit | Maximum number of results to return. Default is 250. | Optional | 
| email_addresses | CSV list or array of email addresses. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.itemId | string | The item ID. | 
| EWS.Items.mailbox | string | The mailbox address where the item was found. | 
| EWS.Items.subject | string | The subject of the email. | 
| EWS.Items.toRecipients | Unknown | List of recipient email addresses. | 
| EWS.Items.sender | string | Sender email address. | 
| EWS.Items.hasAttachments | boolean | Whether the email has attachments? | 
| EWS.Items.datetimeSent | date | Sent time of the email. | 
| EWS.Items.datetimeReceived | date | Received time of the email. | 


#### Command Example

```!ews-search-mailboxes filter="subject:Test" limit=1```

#### Human Readable Output

>|datetimeReceived|datetimeSent|hasAttachments|itemId|mailbox|sender|subject|toRecipients|
>|---|---|---|---|---|---|---|---|
>| 2019-08-11T11:00:28Z | 2019-08-11T11:00:28Z |false | AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGACASFAACYCKjWAnXDFrfsdhdnfkanpAAA=|<a href="mailto:test2@demistodev.onmicrosoft.com">test2@demistodev.onmicrosoft.com</a>|John Smith|test report|<a href="mailto:dem@demistodev.onmicrosoft.com">dem@demistodev.onmicrosoft.com</a>| |

#### Context Example

```json
{
    "EWS": {
        "Items": {
            "itemId": "AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGACASFAACYCKjWAnXDFrfsdhdnfkanpAAA=", 
            "sender": "John Smith", 
            "datetimeReceived": "2019-08-11T11:00:28Z", 
            "hasAttachments": "false", 
            "toRecipients": [
                "dem@demistodev.onmicrosoft.com"
            ], 
            "mailbox": "test2@demistodev.onmicrosoft.com", 
            "datetimeSent": "2019-08-11T11:00:28Z", 
            "subject": "test report "
        }
    }
}
```


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
| is-public | Whether the target folder is a public folder. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.newItemID | string | The item ID after move. | 
| EWS.Items.messageID | string | The item message ID. | 
| EWS.Items.itemId | string | The original item ID. | 
| EWS.Items.action | string | The action taken. The value will be "moved". | 

### ews-delete-items

***
Delete items from mailbox. This command requires eDiscovery permissions to the Exchange Server. For more information, see the EWSv2 integration documentation.


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

#### Command Example

```!ews-delete-items item-ids=VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA= delete-type=soft target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

>|action|itemId|messageId|
>|---|---|---|
>| soft-deleted | VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA= |<message_id>|

#### Context Example

```json
{
    "EWS": {
        "Items": {
            "action": "soft-deleted", 
            "itemId": "VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA=", 
            "messageId": "&lt;messaage_id&gt;"
        }
    }
}
```

### ews-search-mailbox

***
Searches for items in the specified mailbox. Specific permissions are needed for this operation to search in a target mailbox other than the default.


#### Base Command

`ews-search-mailbox`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search query string. For more information about the query syntax, see the Microsoft documentation: <https://msdn.microsoft.com/en-us/library/ee693615.aspx>. | Optional | 
| folder-path | The folder path in which to search. If empty, searches all the folders in the mailbox. | Optional | 
| limit | Maximum number of results to return. Default is 100. | Optional | 
| target-mailbox | The mailbox on which to apply the search. | Optional | 
| is-public | Whether the folder is a Public Folder?. Possible values are: True, False. | Optional | 
| message-id | The message ID of the email. This will be ignored if a query argument is provided. | Optional | 
| selected-fields | A CSV list of fields to retrieve. Possible values are: . Default is all. | Optional | 
| surround_id_with_angle_brackets | Whether to surround the message ID with angle brackets (&lt;&gt;) if it does not exist. Default is 'True'. | Optional | 



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
| EWS.Items.receivedBy | Unknown | Email received by address. | 
| EWS.Items.messageId | string | Email message ID. | 
| EWS.Items.body | string | Body of the email \(as HTML\). | 
| EWS.Items.FileAttachments.attachmentId | unknown | Attachment ID of the file attachment. | 
| EWS.Items.ItemAttachments.attachmentId | unknown | Attachment ID of the item attachment. | 
| EWS.Items.FileAttachments.attachmentName | unknown | Attachment name of the file attachment. | 
| EWS.Items.ItemAttachments.attachmentName | unknown | Attachment name of the item attachment. | 
| EWS.Items.isRead | String | The read status of the email. | 


#### Command Example

```!ews-search-mailbox query="subject:"Get Attachment Email" target-mailbox=test@demistodev.onmicrosoft.com limit=1```

#### Human Readable Output

>|sender|subject|hasAttachments|datetimeReceived|receivedBy|author|toRecipients|
>|---|---|---|---|---|---|---|
>| test2@demistodev.onmicrosoft.com | Get Attachment Email |true |2019-08-11T10:57:37Z|test@demistodev.onmicrosoft.com|test2@demistodev.onmicrosoft.com|test@demistodev.onmicrosoft.com|

#### Context Example

```json
{
    "EWS": {
        "Items": {
            "body": "&lt;html&gt;\r\n&lt;head&gt;\r\n&lt;meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"&gt;\r\n&lt;style type=\"text/css\" style=\"display:none;\"&gt;&lt;!-- P {margin-top:0;margin-bottom:0;} --&gt;&lt;/style&gt;\r\n&lt;/head&gt;\r\n&lt;body dir=\"ltr\"&gt;\r\n&lt;div id=\"divtagrapper\" style=\"font-size:12pt;color:#000000;font-family:Calibri,Helvetica,sans-serif;\" dir=\"ltr\"&gt;\r\n&lt;p style=\"margin-top:0;margin-bottom:0\"&gt;Some text inside email&lt;/p&gt;\r\n&lt;/div&gt;\r\n&lt;/body&gt;\r\n&lt;/html&gt;\r\n", 
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
                }
            ], 
            "isRead": true, 
            "messageId": "&lt;mesage_id&gt;", 
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

### ews-get-contacts

***
Retrieves contacts for a specified mailbox.


#### Base Command

`ews-get-contacts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target-mailbox | The mailbox for which to retrieve the contacts. | Optional | 
| limit | Maximum number of results to return. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Email.EwsContacts.displayName | Unknown | The contact name. | 
| Account.Email.EwsContacts.lastModifiedTime | Unknown | The time that the contact was last modified. | 
| Account.Email.EwsContacts.emailAddresses | Unknown | Phone numbers of the contact. | 
| Account.Email.EwsContacts.physicalAddresses | Unknown | Physical addresses of the contact. | 
| Account.Email.EwsContacts.phoneNumbers.phoneNumber | Unknown | Email addresses of the contact. | 


#### Command Example

```!ews-get-contacts limit="1"```

#### Human Readable Output

>|changekey|culture|datetimeCreated|datetimeReceived|datetimeSent|displayName|emailAddresses|fileAs|fileAsMapping|givenName|id|importance|itemClass|lastModifiedName|lastModifiedTime|postalAddressIndex|sensitivity|subject|uniqueBody|webClientReadFormQueryString|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| EABYACAADcsxRwRjq/zTrN6vWSzKAK1Dl3N | en-US |2019-08-05T12:35:36Z |2019-08-05T12:35:36Z|2019-08-05T12:35:36Z|Contact Name|some@dev.microsoft.com|Contact Name|LastCommaFirst|Contact Name|AHSNNK3NQNcasnc3SAS/zTrN6vWSzK4OWAAAAAAEOAADrxRwRjq/zTrNFSsfsfVWAAK1KsF3AAA=|Normal|IPM.Contact|John Smith|2019-08-05T12:35:36Z|None|Normal|Contact Name| |<https://outlook.office365.com/owa/?ItemID>=***|

#### Context Example

```json
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
            "uniqueBody": "&lt;html&gt;&lt;body&gt;&lt;/body&gt;&lt;/html&gt;", 
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

### ews-resolve-name

***
This operation verifies aliases and matches display names to the correct mailbox user. It handles one ambiguous name at a time. If there are multiple potential matches, all will be returned, but limited to a maximum of 100 candidates.
#### Base Command

`ews-resolve-name`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                  | **Required** |
| --- |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| identifier | The text value of this argument is used to resolve names against the following fields: First name, Last name, Display name, Full name, Office, Alias, SMTP address. Eg. `John Doe` or `sip:johndoe@example.com`. | Required | 
| full-contact-data | Describes whether the full contact details for public contacts for a resolved name are returned. Possible values are: True, False.                                                                               | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.ResolvedNames.FullContactInfo.contactSource | String | Whether the contact is located in the Exchange store or Active Directory Domain Services \(AD DS\). | 
| EWS.ResolvedNames.FullContactInfo.culture | String | Represents the culture for a given item in a mailbox. | 
| EWS.ResolvedNames.FullContactInfo.displayName | String | The display name of a contact. | 
| EWS.ResolvedNames.FullContactInfo.ItemId | String | Contains the unique identifier and change key of an item in the Exchange store. | 
| EWS.ResolvedNames.FullContactInfo.emailAddresses | String | Represents a collection of email addresses for a contact. | 
| EWS.ResolvedNames.FullContactInfo.givenName | String | Contains a contact's given name. | 
| EWS.ResolvedNames.FullContactInfo.importance | String | Describes the importance of an item. | 
| EWS.ResolvedNames.FullContactInfo.initials | String | Represents the initials of a contact. | 
| EWS.ResolvedNames.FullContactInfo.phoneNumbers.label | String | The following are the possible values for this attribute: AssistantPhone, BusinessFax, BusinessPhone, BusinessPhone2, Callback, CarPhone, CompanyMainPhone, HomeFax, HomePhone, HomePhone2, Isdn, MobilePhone, OtherFax, OtherTelephone, Pager, PrimaryPhone, RadioPhone, Telex, TtyTddPhone | 
| EWS.ResolvedNames.FullContactInfo.phoneNumbers.phoneNumber | String | The phone number of the contact | 
| EWS.ResolvedNames.FullContactInfo.physicalAddresses.city | String | The physical addresses city associated with the contact. | 
| EWS.ResolvedNames.FullContactInfo.physicalAddresses.country | String | The physical addresses country associated with the contact. | 
| EWS.ResolvedNames.FullContactInfo.physicalAddresses.label | String | The physical addresses label associated with the contact. | 
| EWS.ResolvedNames.FullContactInfo.physicalAddresses.state | String | The physical addresses state associated with the contact. | 
| EWS.ResolvedNames.FullContactInfo.physicalAddresses.street | String | The physical addresses street associated with the contact. | 
| EWS.ResolvedNames.FullContactInfo.physicalAddresses.zipcode | String | The physical addresses zipcode associated with the contact. | 
| EWS.ResolvedNames.FullContactInfo.postalAddressIndex | String | Represents the display types for physical addresses. | 
| EWS.ResolvedNames.FullContactInfo.sensitivity | String | Indicates the sensitivity level of an item. | 
| EWS.ResolvedNames.email_address | String | The primary SMTP address of a mailbox user. | 
| EWS.ResolvedNames.mailbox_type | String | The type of mailbox that is represented by the email address. | 
| EWS.ResolvedNames.name | String | The name of a mailbox user. | 
| EWS.ResolvedNames.routing_type | String | The address type for the mailbox | 


#### Command example

```!ews-resolve-name identifier=`example@example.com` full-contact-data=True```

#### Context Example

```json
{
    "EWS": {
        "ResolvedNames": {
            "FullContactInfo": {
                "contactSource": "ActiveDirectory",
                "culture": "en-US",
                "displayName": "ews-2016-test EW2016.",
                "emailAddresses": [
                    "example-sec@example.com",
                    "example@example.com"
                ],
                "givenName": "ews-2016-test",
                "importance": "Normal",
                "initials": "EW2016",
                "phoneNumbers": [
                    {
                        "label": "AssistantPhone",
                        "phoneNumber": null
                    },
                    {
                        "label": "BusinessFax",
                        "phoneNumber": null
                    },
                    {
                        "label": "BusinessPhone",
                        "phoneNumber": null
                    },
                    {
                        "label": "HomePhone",
                        "phoneNumber": null
                    },
                    {
                        "label": "MobilePhone",
                        "phoneNumber": null
                    },
                    {
                        "label": "Pager",
                        "phoneNumber": null
                    }
                ],
                "physicalAddresses": [
                    {
                        "city": null,
                        "country": null,
                        "label": "Business",
                        "state": null,
                        "street": null,
                        "zipcode": null
                    }
                ],
                "postalAddressIndex": "None",
                "sensitivity": "Normal"
            },
            "email_address": "ews-2016-test@lab-demisto.com",
            "mailbox_type": "Mailbox",
            "name": "ews-2016-test EW2016.",
            "routing_type": "SMTP"
        }
    }
}
```

#### Human Readable Output

>### Resolved Names

>| primary_email_address         |name|mailbox_type|routing_type|
>|-------------------------------|---|---|---|
>| ews-2016-test@lab-demisto.com | ews-2016-test EW2016. | Mailbox | SMTP |


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

#### Command Example

```!ews-get-out-of-office target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

>|end|externalAudienc|mailbox|start|state|
>|---|---|---|---|---|
>| 2019-08-12T13:00:00Z | all |test@demistodev.onmicrosoft.com|2019-08-11T13:00:00Z|Disabled|

#### Context Example

```json
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


### ews-recover-messages

***
Recovers messages that were soft-deleted.


#### Base Command

`ews-recover-messages`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message-ids | A CSV list of message IDs. Run the py-ews-delete-items command to retrieve the message IDs. | Required | 
| target-folder-path | The folder path to recover the messages to. Default is Inbox. | Required | 
| target-mailbox | The mailbox in which the messages found. If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox. | Optional | 
| is-public | Whether the target folder is a Public Folder. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.itemId | Unknown | The item ID of the recovered item. | 
| EWS.Items.messageId | Unknown | The message ID of the recovered item. | 
| EWS.Items.action | Unknown | The action taken on the item. The value will be 'recovered'. | 

#### Command Example

```!ews-recover-messages message-ids=&lt;DFVDFmvsCSCS.com&gt; target-folder-path=Moving target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

>|action|itemId|messageId|
>|---|---|---|
>| recovered | AAVCSVS1hN2NkLThmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed33wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVyFtlscfxxd/AAA= |DFVDFmvsCSCS.com|

#### Context Example

```json
{
    "EWS": {
        "Items": {
            "action": "recovered", 
            "itemId": "AAVCSVS1hN2NkLThmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed33wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVyFtlscfxxd/AAA=", 
            "messageId": "&lt;DFVDFmvsCSCS.com&gt;"
        }
    }
}
```

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

#### Command Example

```!ews-create-folder folder-path=Inbox new-folder-name="Created Folder" target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

```Folder Inbox\Created Folder created successfully```


### ews-mark-item-as-junk

***
Marks an item as junk. This is commonly used to block an email address. For more information, see the Microsoft documentation: <https://msdn.microsoft.com/en-us/library/office/dn481311(v=exchg.150).aspx>


#### Base Command

`ews-mark-item-as-junk`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-id | The item ID to mark as junk. | Required | 
| move-items | Whether to move the item from the original folder to the junk folder. Possible values are: yes, no. Default is yes. | Optional | 
| target-mailbox | If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

```!ews-mark-item-as-junk item-id=AAMkcSQ0NmFkOhmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUcsBJebinpkUAAAAAAEMASFDkUAAAfxuiSAAA= move-items=yes target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

>|action|itemId|
>|---|---|
>| marked-as-junk |AAMkcSQ0NmFkOhmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUcsBJebinpkUAAAAAAEMASFDkUAAAfxuiSAAA=|

#### Context Example

```json
{
    "EWS": {
        "Items": {
            "action": "marked-as-junk", 
            "itemId": "AAMkcSQ0NmFkOhmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUcsBJebinpkUAAAAAAEMASFDkUAAAfxuiSAAA="
        }
    }
}
```

### ews-find-folders

***
Retrieves information for folders for a specified mailbox. Only folders with read permissions will be returned. Your visual folders on the mailbox, such as "Inbox", are under the folder "Top of Information Store".


#### Base Command

`ews-find-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target-mailbox | The mailbox on which to apply the command. | Optional | 
| is-public | Whether to find Public Folders. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Folders.name | string | Folder name. | 
| EWS.Folders.id | string | Folder ID. | 
| EWS.Folders.totalCount | Unknown | Number of items in folder. | 
| EWS.Folders.unreadCount | number | Number of unread items in folder | 
| EWS.Folders.changeKey | number | Folder change key. | 
| EWS.Folders.childrenFolderCount | number | Number of sub-folders. | 

#### Command Example

```!ews-find-folders target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

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

#### Context Example

```json
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
        ]
    }
}
```

### ews-get-items-from-folder

***
Retrieves items from a specified folder in a mailbox. The items are order by the item created time, most recent is first.


#### Base Command

`ews-get-items-from-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder-path | The folder path from which to get the items. | Required | 
| limit | Maximum number of items to return. Default is 100. | Optional | 
| target-mailbox | The mailbox to on which to apply the command. | Optional | 
| is-public | Whether the folder is a Public Folder. Default is 'False'. Possible values are: True, False. | Optional | 
| get-internal-item | If the email item contains another email as an attachment (EML or MSG file), whether to retrieve the EML/MSG file attachment. Can be "yes" or "no". Default is "no". Possible values are: yes, no. Default is no. | Optional | 


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
| EWS.Items.categories | String | Categories of the email. | 


#### Command Example

```!ews-get-items-from-folder folder-path=Test target-mailbox=test@demistodev.onmicrosoft.com limit=1```

#### Human Readable Output

>|sender|subject|hasAttachments|datetimeReceived|receivedBy|author|toRecipients|itemId|
>|---|---|---|---|---|---|---|---|
>| test2@demistodev.onmicrosoft.com |Get Attachment Email|true|2019-08-11T10:57:37Z|test@demistodev.onmicrosoft.com|test2@demistodev.onmicrosoft.com|test@demistodev.onmicrosoft.com|AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAA=|

#### Context Example

```json
{
    "EWS": {
        "Items": {
            "body": "&lt;html&gt;\r\n&lt;head&gt;\r\n&lt;meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"&gt;\r\n&lt;style type=\"text/css\" style=\"display:none;\"&gt;&lt;!-- P {margin-top:0;margin-bottom:0;} --&gt;&lt;/style&gt;\r\n&lt;/head&gt;\r\n&lt;body dir=\"ltr\"&gt;\r\n&lt;div id=\"divtagdefaultwrapper\" style=\"font-size:12pt;color:#000000;font-family:Calibri,Helvetica,sans-serif;\" dir=\"ltr\"&gt;\r\n&lt;p style=\"margin-top:0;margin-bottom:0\"&gt;Some text inside email&lt;/p&gt;\r\n&lt;/div&gt;\r\n&lt;/body&gt;\r\n&lt;/html&gt;\r\n", 
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
                }
                            ], 
            "isRead": true, 
            "messageId": "&lt;message_id&gt;", 
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

### ews-get-items

***
Retrieves items by item ID.


#### Base Command

`ews-get-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-ids | A CSV list if item IDs. | Required | 
| target-mailbox | The mailbox on which to run the command on. | Optional | 


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
| EWS.Items.categories | String | Categories of the email. | 
| Email.CC | String | Email addresses CC'ed to the email. | 
| Email.BCC | String | Email addresses BCC'ed to the email. | 
| Email.To | String | The recipient of the email. | 
| Email.From | String | The sender of the email. | 
| Email.Subject | String | The subject of the email. | 
| Email.Text | String | The plain-text version of the email. | 
| Email.HTML | String | The HTML version of the email. | 
| Email.HeadersMap | String | The headers of the email. | 



#### Command Example

```!ews-get-items item-ids=AAMkADQ0NmFkODFkLWQ4MDEtNDFDFZjNTMxNwBGAAAAAAA4kxhFFAfxw+jAAA= target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

```
Identical outputs to ews-get-items-from-folder command.
```

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
| is-public | Whether the destination folder is a Public Folder. Default is "False". Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.movedToMailbox | string | The mailbox wo which the item was moved. | 
| EWS.Items.movedToFolder | string | The folder to which the item was moved. | 
| EWS.Items.action | string | The action taken on the item. The value will be "moved". | 

#### Command Example

```!ews-move-item-between-mailboxes item-id=AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NFSFSyNzBkNABGAAAAAACYCKjWAjq/zTrN6vWSzK4OWAAK2ISFSA= destination-folder-path=Moving destination-mailbox=test@demistodev.onmicrosoft.com source-mailbox=test2@demistodev.onmicrosoft.com```

#### Human Readable Output

```
Item was moved successfully.
```

#### Context Example

```json
{
    "EWS": {
        "Items": {
            "movedToMailbox": "test@demistodev.onmicrosoft.com", 
            "movedToFolder": "Moving"
        }
    }
}
```

### ews-get-folder

***
Retrieves a single folder.


#### Base Command

`ews-get-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target-mailbox | The mailbox on which to apply the search. | Optional | 
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

#### Command Example

```!ews-get-folder folder-path=demistoEmail target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

>|changeKey|childrenFolderCount|id|name|totalCount|unreadCount|
>|---|---|---|---|---|---|
>| ***yFtCdJSH |0|AAMkADQ0NmFkODFkLWQ4MDEtNDE4Mi1hN2NlsjflsjfSF=|demistoEmail|1|0|


#### Context Example

```json
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

### ews-get-autodiscovery-config

***
Returns the auto-discovery information. Can be used to manually configure the Exchange Server.


#### Base Command

`ews-get-autodiscovery-config`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!ews-get-autodiscovery-config```

#### Human Readable Output

>|api_version|auth_type|build|service_endpoint|
>|---|---|---|---|
>| Exchange2016 |###|--|<https://outlook.office365.com/EWS/Exchange.asmx>|


### ews-expand-group

***
Expands a distribution list to display all members. By default, expands only first layer of the distribution list. If recursive-expansion is "True", the command expands nested distribution lists and returns all members.


#### Base Command

`ews-expand-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email-address | Email address of the group to expand. | Required | 
| recursive-expansion | Whether to enable recursive expansion. Default is "False". Possible values are: True, False. Default is False. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

```!ews-expand-group email-address="TestPublic" recursive-expansion="False"```

#### Human Readable Output

>|displayNam|mailbox|mailboxtype|
>|---|---|---|
>| John Wick|john@wick.com|MailBox|

#### Context Example

```json
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

### ews-mark-items-as-read

***
Marks items as read or unread.


#### Base Command

`ews-mark-items-as-read`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-ids | A CSV list of item IDs. | Required | 
| operation | How to mark the item. Can be "read" or "unread". Default is "read". Possible values are: read, unread. Default is read. | Optional | 
| target-mailbox | The mailbox on which to run the command. If empty, the command will be applied on the default mailbox. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EWS.Items.action | String | The action that was performed on item. | 
| EWS.Items.itemId | String | The ID of the item. | 
| EWS.Items.messageId | String | The message ID of the item. | 


#### Command Example

```!ews-mark-items-as-read item-ids=AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA= operation=read target-mailbox=test@demistodev.onmicrosoft.com```

#### Human Readable Output

>|action|itemId|messageId|
>|---|---|---|
>| mark-as-read|AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA=|id|

#### Context Example

```json
{
    "EWS": {
        "Items": {
            "action": "marked-as-read", 
            "itemId": "AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA= ", 
            "messageId": "&lt;message_id&gt;"
        }
    }
}
```

### ews-get-items-as-eml

***
Retrieves items by item ID and uploads it's content as eml file.


#### Base Command

`ews-get-items-as-eml`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-id | The item ID of item to upload as and EML file. | Required | 
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
| File.EntryID | String | EntryID of the file | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

### send-mail

***
Sends an email using EWS.

#### Base Command

`send-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | A CSV list of email addresses for the 'to' field. | Required | 
| cc | A CSV list of email addresses for the 'cc' field. | Optional | 
| bcc | A CSV list of email addresses for the 'bcc' field. | Optional | 
| subject | Subject for the email to be sent. | Required | 
| replyTo | The email address specified in the 'reply to' field. | Optional | 
| body | The contents (body) of the email to send. This argument overrides the "htmlBody" argument if the "bodyType" argument is Text. | Optional | 
| htmlBody | HTML formatted content (body) of the email to be sent. This argument overrides the "body" argument if the "bodyType" argument is HTML. | Optional | 
| bodyType | The message response body type. Possible values are: Text, HTML. Default is Text. | Optional | 
| attachIDs | A CSV list of War Room entry IDs that contain files, and are used to attach files to the outgoing email. For example: attachIDs=15@8,19@8. | Optional | 
| attachNames | A CSV list of names of attachments to send. Should be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A CSV list of CIDs to embed attachments within the email itself. | Optional | 
| raw_message | Raw email message from MimeContent type. | Optional | 
| from | The email address from which to send mail. | Optional | 
| handle_inline_image | Whether to handle inline images in the HTML body. When set to 'True', inline images will be extracted from the HTML and attached to the email as an inline attachment object. Note that in some cases, attaching the image as an object may cause the image to disappear when replying to the email. Additionally, sending the image in the html body as base64 data (inline image) may cause the image to disappear if the image is too large or recognized as malicious and subsequently deleted. Possible values are: True, False. Default is True. | Optional | 

#### Context Output

There is no context output for this command.

### reply-mail

***
Replies to an email using EWS.

#### Command Example

```!send-mail body="hello this is a test" subject=Hi to=avishai@demistodev.onmicrosoft.com```

#### Human Readable Output

>### Sent email

>|attachments|from|subject|to|
>|---|---|---|---|
>|  | avishai@demistodev.onmicrosoft.com | Hi | avishai@demistodev.onmicrosoft.com |


#### Base Command

`reply-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inReplyTo | ID of the item to reply to. | Required | 
| to | A CSV list of email addresses for the 'to' field. | Required | 
| cc | A CSV list of email addresses for the 'cc' field. | Optional | 
| bcc | A CSV list of email addresses for the 'bcc' field. | Optional | 
| subject | Subject for the email to be sent. | Optional | 
| body | The contents (body) of the email to be sent. | Optional | 
| htmlBody | HTML formatted content (body) of the email to be sent. This argument overrides the "body" argument. | Optional | 
| attachIDs | A CSV list of War Room entry IDs that contain files, and are used to attach files to the outgoing email. For example: attachIDs=15@8,19@8. | Optional | 
| attachNames | A CSV list of names of attachments to send. Should be the same number of elements as attachIDs. | Optional | 
| attachCIDs | A CSV list of CIDs to embed attachments within the email itself. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

```!reply-mail item_id=AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq/zTrN6vWSzK4OWAAAAAAEMAADrxRwRjq/zTrN6vWSzK4OWAAPYQGFeAAA= body=hello subject=hi to="avishai@demistodev.onmicrosoft.com"```

#### Human Readable Output

>### Sent email

>|attachments|from|subject|to|
>|---|---|---|---|
>|  | avishai@demistodev.onmicrosoft.com | hi | avishai@demistodev.onmicrosoft.com |


## Additional Information

#### EWS Permissions

To perform actions on mailboxes of other users, and to execute searches on the Exchange server, you need specific permissions. For a comparison between Delegate and Impersonation permissions, see the [Microsoft documentation](https://blogs.msdn.microsoft.com/exchangedev/2009/06/15/exchange-impersonation-vs-delegate-access/)

| **Permission** | **Use Case** | **How to Configure** |
| --- | --- | --- |
|Delegated|One-to-one relationship between users.|Read more [here](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/delegate-access-and-ews-in-exchange).|
|Impersonation|A single account needs to access multiple mailboxes.|Read more [here](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-configure-impersonation).|
|eDiscovery|A single account needs to access multiple mailboxes.|Read more [here](https://docs.microsoft.com/en-us/Exchange/policy-and-compliance/ediscovery/assign-permissions?view=exchserver-2019).|
|Compliance Search|Perform searches across mailboxes and get an estimate of the results.|Read more [here](https://docs.microsoft.com/en-us/office365/securitycompliance/permissions-in-the-security-and-compliance-center).|


#### New-Compliance Search

The EWS v2 integration uses remote ps-session to run commands of compliance search as part of Office 365. To check if your account can connect to Office 365 Security &amp; Compliance Center via powershell, check the following [steps](https://docs.microsoft.com/en-us/powershell/exchange/office-365-scc/connect-to-scc-powershell/connect-to-scc-powershell?view=exchange-ps). New-Compliance search is a long-running task which has no limitation of searched mailboxes and therefore the suggestion is to use``` Office 365 Search and Delete```playbook. New-Compliance search returns statistics of matched content search query and doesn't return preview of found emails in contrast to```ews-search-mailboxes```command.

## Troubleshooting

For troubleshooting information, see the [EWS V2 Troubleshooting](https://xsoar.pan.dev/docs/reference/articles/EWS_V2_Troubleshooting).