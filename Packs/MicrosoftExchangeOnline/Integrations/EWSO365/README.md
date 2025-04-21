Exchange Web Services (EWS) provides the functionality to enable client applications to communicate with the Exchange server. EWS provides access to much of the same data that is made available through Microsoft Office Outlook.

The EWS O365 integration implants EWS leading services. The integration allows getting information on emails and activities in a target mailbox, and some active operations on the mailbox such as deleting emails and attachments or moving emails from folder to folder.

## Retirement of RBAC Application Impersonation

As of February 2025, the Impersonation access type of the integration is deprecated by Microsoft, read about it [here](https://techcommunity.microsoft.com/blog/exchange/critical-update-applicationimpersonation-rbac-role-deprecation-in-exchange-onlin/4295762).
To avoid disruptions, it is imperative that administrators begin transitioning their applications immediately.
To identify accounts using the ApplicationImpersonation role use the Exchange Online PowerShell command:
`Get-ManagementRoleAssignment -Role ApplicationImpersonation -GetEffectiveUsers -Delegating:$false`

## Use Cases

The EWS integration can be used for the following use cases.

* Monitor a specific email account and create incidents from incoming emails to the defined folder.  
    Follow the instructions in the [Fetched Incidents Data section](https://xsoar.pan.dev/docs/reference/integrations/ewso365#fetched-incidents-data).

* Search for an email message across mailboxes and folders.  

    Use the `ews-search-mailbox` command to search for all emails in a specific folder within the target mailbox.  
     Use the query argument to narrow the search for emails sent from a specific account and more.
    This command retrieves the _ItemID_ field for each email item listed in the results. The `ItemID` value can be used in the `ews-get-items` command in order to get more information about the email item itself.

* Get email attachment information.  
    Use the `ews-get-attachment` command to retrieve information on one attachment or all attachments of a message at once. It supports both file attachments and item attachments (e.g., email messages).

* Delete email items from a mailbox.  
    First, make sure you obtain the email item ID. The item ID can be obtained with one of the integration’s search commands.  
    Use the `ews-delete-items`<span> command </span>to delete one or more items from the target mailbox in a single action.  
    A less common use case is to remove emails that were marked as malicious from a user’s mailbox.  
    You can delete the items permanently (hard delete) or delete the items (soft delete), so they can be recovered by running the `ews-recover-messages` command.

## Architecture

This integration is based on the `exchangelib` python module. For more information about the module, check the [documentation](https://ecederstrand.github.io/exchangelib/).


## Set up the Third Party System

There are two application authentication methods available.
Follow your preferred method's guide on how to use the admin consent flow in order to receive your authentication information:

* [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
    To allow access to EWS O365, an administrator has to approve the Demisto app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-ews-o365).
    After authorizing the Demisto app, you will get an ID, Token, and Key, which needs to be added to the integration instance configuration's corresponding fields.


* [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application) - Client Credential Flow.

## Authentication

For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).

## Permissions

In order to function as expected, the service account should have:

**Impersonation rights** (deprecated) - In order to perform actions on the target mailbox of other users, the _service account_ must be part of the `ApplicationImpersonation` role. For more information and instructions on how to set up the permission, see [Microsoft Documentation](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/impersonation-and-ews-in-exchange).
Most commands require this permission to function correctly. This permission is specified in each relevant command's Permission section. For more information, see [Microsoft Documentation](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/impersonation-and-ews-in-exchange).

**eDiscovery** permissions to the Exchange Server. For users to be able to use Exchange Server In-Place eDiscovery, they must be added to the Discovery Management role group. Members of the Discovery Management role group have Full Access mailbox permissions to the default discovery mailbox, which is called Discovery Search Mailbox, including access to sensitive message content. For more information, see the [Microsoft documentation](https://technet.microsoft.com/en-us/library/dd298059(v=exchg.160).aspx).
The need for this permission is specified in each relevant command's Permission section.

**full_access_as_app** - The _application used for authentication_ requires this permission to gain access to the Exchange Web Services.
To set this permission follow these steps:

1. Navigate to **Home** > **App registrations**.
2. Search for your app under *all applications*.
3. Click **API permissions** > **Add permission**.
4. Search for `Office 365 Exchange Online` API > `Application Permission`> `full_access_as_app` permission.

For more information on this permission, see [the Microsoft documentation](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth#configure-for-app-only-authentication).

To limit the application's permissions to only specific mailboxes, follow the [Microsoft documentation](https://docs.microsoft.com/en-us/graph/auth-limit-mailbox-access). Note that it may take about an hour for permissions changes to take effect.

## Configure Integration on Cortex

| **Parameter** | **Description** |**Required**|
| --- | --- | --- |
| ID / Application ID | ID can be received after following the System Integration Setup (Device side steps). | False |
| Token / Tenant ID | Token can be received after following the System Integration Setup (Device side steps). | False |
| Key / Application Secret | Key can be received after following the System Integration Setup (Device side steps). | False |
| Azure Cloud | Azure Cloud environment. Options are: _Worldwide_ (The publicly accessible Azure Cloud), _US GCC_ (Azure cloud for the USA Government Cloud Community), _US GCC-High_ (Azure cloud for the USA Government Cloud Community High), _DoD_ (Azure cloud for the USA Department of Defense), _Germany_ (Azure cloud for the German Government), _China_ (Azure cloud for the Chinese Government ) | False|
| Email Address | Mailbox to run commands on and to fetch incidents from. To use this functionality, your account must have delegation for the account specified. For more information, see https://xsoar.pan.dev/docs/reference/integrations/ewso365/#additional-information | True |
| UPN Address | When provided, the target mailbox if it's different from the Email Address. Otherwise, the Email Address is used. | False |
| Name of the folder from which to fetch incidents | Supports Exchange Folder ID and sub-folders, e.g., Inbox/Phishing. | True |
| Access Type | Run the commands using `Delegate` or `Impersonation` access types. | False |
| Public Folder |  Whether the folder to be fetched from is public. Public folders can store and organize emails on specific topics or projects. Public folders are usually listed under the "Public Folders" section in the navigation pane in the product itself. | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Maximum number of incidents per fetch (up to 200). Performance might be affected by a value higher than 50. |  | False |
| Mark fetched emails as read | | False |
| Timeout (in seconds) for HTTP requests to Exchange Server |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Run as a separate process (protects against memory depletion) |  | False |
| Use a self-deployed Azure Application | Select this checkbox if you are using a self-deployed Azure application. | False |
| Incidents Fetch Interval |  | False |
| Skip unparsable emails during fetch incidents | Whether to skip unparsable emails during incident fetching. | False |
| What time field should we filter incidents by? | Default is to filter by received-time, which works well if the folder is an "Inbox". But for a folder emails are dragged into for attention, if we filter by received-time, out-of-order processing of emails means some are ignored. Filtering by modified-time works better for such a scenario. This works best if any modifications \(such as tagging\) happens before moving the email into the folder, such that the move into the folder is the last modification, and triggers Cortex XSOAR to fetch it as an incident. | False |

## Fetch Incidents

The integration imports email messages from the destination folder in the target mailbox as incidents. If the message contains any attachments, they are uploaded to the War Room as files. If the attachment is an email, Cortex XSOAR fetches information about the attached email and downloads all of its attachments (if there are any) as files.

To use Fetch incidents, configure a new instance and select the `Fetches incidents` option in the instance settings.

**IMPORTANT**:  
`First fetch timestamp` field is used to determine how much time back to fetch incidents from. The default value is the previous 10 minutes, Meaning, if this is the first time emails are fetched from the destination folder, all emails from 10 minutes prior to the instance configuration and up to the current time will be fetched.
When set to get a long period of time, the `Timeout` field might need to be set to a higher value.

Pay special attention to the following fields in the instance settings:

- `Email Address` – mailbox to fetch incidents from.  
- `Name of the folder from which to fetch incidents` – use this field to configure the destination folder from where emails should be fetched. The default is Inbox folder.

#### Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

If Exchange is configured with an international flavor, `Inbox` will be named according to the configured language.

## Commands

<details>
<summary><h3 style={{display: 'inline'}}>ews-get-attachment</h3></summary>

### ews-get-attachment

Retrieves the actual attachments from an email message. To get all attachments for a message, only specify the item-id argument.

#### Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id |The ID of the email message for which to get the attachments.|Required|
|target-mailbox |The mailbox in which this attachment was found. If empty, the default mailbox is used. Otherwise, the user might require impersonation rights to this mailbox.|Optional|
|attachment-ids |The attachments IDs to get. If none, all attachments will be retrieved from the message. Support multiple attachments with comma-separated values or an array. |Optional|

#### Outputs

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

#### Examples

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

</details>
<details>
<summary><h3 style={{display: 'inline'}}>ews-delete-attachment</h3></summary>

### ews-delete-attachment

Deletes the attachments of an item (email message).

#### Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id|The ID of the email message for which to delete attachments.|Required|
|target-mailbox|The mailbox in which this attachment was found. If empty, the default mailbox is used. Otherwise, the user might require impersonation rights to this mailbox.|Optional|
|attachment-ids|A comma-separated list (or array) of attachment IDs to delete. If empty, all attachments will be deleted from the message.|Optional|

#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.FileAttachments.attachmentId|string|The ID of the deleted attachment, in case of file attachment.|
|EWS.Items.ItemAttachments.attachmentId|string|The ID of the deleted attachment, in case of other attachment (for example, "email").|
|EWS.Items.FileAttachments.action|string|The deletion action in case of file attachment. This is a constant value: 'deleted'.|
|EWS.Items.ItemAttachments.action|string|The deletion action in case of other attachment (for example, "email"). This is a constant value: 'deleted'.|

#### Examples

```
!ews-delete-attachment item-id=AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAA= target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

>|action|attachmentId|
>|--- |--- |
>|deleted|AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAABEgAQAIUht2vrOdErec33=|

##### Context Example

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

</details>

<details>
<summary><h3 style={{display: 'inline'}}>ews-get-searchable-mailboxes</h3></summary>

### ews-get-searchable-mailboxes

Get a list of searchable mailboxes.

#### Permissions

Requires eDiscovery permissions to the Exchange Server. For more information see the [Microsoft documentation](https://technet.microsoft.com/en-us/library/dd298059(v=exchg.160).aspx).

#### Limitations

No known limitations.

#### Inputs

There are no input arguments for this command.

#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Mailboxes.mailbox|string|Addresses of the searchable mailboxes.|
|EWS.Mailboxes.mailboxId|string|IDs of the searchable mailboxes.|
|EWS.Mailboxes.displayName|string|The email display name.|
|EWS.Mailboxes.isExternal|boolean|Whether the mailbox is external.|
|EWS.Mailboxes.externalEmailAddress|string|The external email address.|

#### Examples

```
!ews-get-searchable-mailboxes
```

##### Human Readable Output

>|displayName|isExternal|mailbox|mailboxId|
>|--- |--- |--- |--- |
>|test|false|test@demistodev.onmicrosoft.com|/o=Exchange\*\*\*/ou=Exchange Administrative Group ()/cn=\*\*/cn=\*\\*-*\*|

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

</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-move-item</h3></summary>

### ews-move-item

Move an item to a different folder in the mailbox.

#### Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id|The ID of the item to move.|Required|
|target-folder-path|The path to the folder to which to move the item. Complex paths are supported, for example, "Inbox\Phishing".|Required|
|target-mailbox|The mailbox on which to run the command.|Optional|
|is-public|Whether the target folder is a public folder.|Optional|


#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.newItemID|string|The item ID after the move.|
|EWS.Items.messageID|string|The item message ID.|
|EWS.Items.itemId|string|The original item ID.|
|EWS.Items.action|string|The action taken. The value will be "moved".|

#### Examples

```
!ews-move-item item-id=VDAFNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU34cSCSSSfBJebinpkUAAAAAAEMAACyyVyFtlsUQZfBJebinpkUAAAfxuiRAAA= target-folder-path=Moving target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

>|action|itemId|messageId|newItemId|
>|--- |--- |--- |--- |
>|moved|VDAFNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU34cSCSSSfBJebinpkUAAAAAAEMAACyyVyFtlsUQZfBJebinpkUAAAfxuiRAAA||AAVAAAVN2NkLThmZjdmNTZjNTMxFFFFJTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVfafainpkUAAAfxxd+AAA=|

##### Context Example

```
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
```

</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-delete-items</h3></summary>

### ews-delete-items

Delete an item from a mailbox

#### Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-ids|A comma-separated list (or array) of IDs to delete.|Required|
|delete-type|Deletion type. Can be "trash", "soft", or "hard".|Required|
|target-mailbox|The mailbox on which to run the command.|Optional|

#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.itemId|string|The deleted item ID.|
|EWS.Items.messageId|string|The deleted message ID.|
|EWS.Items.action|string|The deletion action. Can be 'trash-deleted', 'soft-deleted', or 'hard-deleted'.|

#### Examples

```
!ews-delete-items item-ids=VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA= delete-type=soft target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

>|action|itemId|messageId|
>|--- |--- |--- |
>|soft-deleted|VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA=||

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
</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-search-mailbox</h3></summary>

### ews-search-mailbox

Searches for items in the specified mailbox. Specific permissions are needed for this operation to search in a target mailbox other than the default.

#### Permissions

Impersonation rights required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|query|The search query string. For more information about the query syntax, see the [Microsoft documentation](https://msdn.microsoft.com/en-us/library/ee693615.aspx).|Optional|
|folder-path|The folder path in which to search. If empty, searches all the folders in the mailbox.|Optional|
|limit|Maximum number of results to return.|Optional|
|target-mailbox|The mailbox on which to apply the search.|Optional|
|is-public|Whether the folder is a public folder?|Optional|
|message-id|The message ID of the email. This will be ignored if a query argument is provided.|Optional|

#### Outputs

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

#### Examples

```
!ews-search-mailbox query="subject:"Get Attachment Email" target-mailbox=test@demistodev.onmicrosoft.com limit=1
```

##### Human Readable Output

>|sender|subject|hasAttachments|datetimeReceived|receivedBy|author|toRecipients|
>|--- |--- |--- |--- |--- |--- |--- |
>|test2@demistodev.onmicrosoft.com|Get Attachment Email|true|2019-08-11T10:57:37Z|test@demistodev.onmicrosoft.com|test2@demistodev.onmicrosoft.com|test@demistodev.onmicrosoft.com|

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


</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-get-contacts</h3></summary>

### ews-get-contacts

Retrieves contacts for a specified mailbox.

#### Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|target-mailbox|The mailbox for which to retrieve the contacts.|Optional|
|limit|Maximum number of results to return.|Optional|

#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|Account.Email.EwsContacts.displayName|Unknown|The contact name.|
|Account.Email.EwsContacts.lastModifiedTime|Unknown|The time that the contact was last modified.|
|Account.Email.EwsContacts.emailAddresses|Unknown|Phone numbers of the contact.|
|Account.Email.EwsContacts.physicalAddresses|Unknown|Physical addresses of the contact.|
|Account.Email.EwsContacts.phoneNumbers.phoneNumber|Unknown|Email addresses of the contact.|

#### Examples

```
!ews-get-contacts limit="1"
```

##### Human Readable Output

>|changekey|culture|datetimeCreated|datetimeReceived|datetimeSent|displayName|emailAddresses|fileAs|fileAsMapping|givenName|id|importance|itemClass|lastModifiedName|lastModifiedTime|postalAddressIndex|sensitivity|subject|uniqueBody|webClientReadFormQueryString|
>|--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |
>|EABYACAADcsxRwRjq/zTrN6vWSzKAK1Dl3N|en-US|2019-08-05T12:35:36Z|2019-08-05T12:35:36Z|2019-08-05T12:35:36Z|Contact Name|some@dev.microsoft.com|Contact Name|LastCommaFirst|Contact Name|AHSNNK3NQNcasnc3SAS/zTrN6vWSzK4OWAAAAAAEOAADrxRwRjq/zTrNFSsfsfVWAAK1KsF3AAA=|Normal|IPM.Contact|John Smith|2019-08-05T12:35:36Z|None|Normal|Contact Name||<https://outlook.office365.com/owa/?ItemID>=***|

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

</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-get-out-of-office</h3></summary>

### ews-get-out-of-office

Retrieves the out-of-office status for a specified mailbox.

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|target-mailbox|The mailbox for which to get the out-of-office status.|Required|


#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|Account.Email.OutOfOffice.state|Unknown|Out-of-office state. The result can be: "Enabled", "Scheduled", or "Disabled".|
|Account.Email.OutOfOffice.externalAudience|Unknown|Out-of-office external audience. Can be "None", "Known", or "All".|
|Account.Email.OutOfOffice.start|Unknown|Out-of-office start date.|
|Account.Email.OutOfOffice.end|Unknown|Out-of-office end date.|
|Account.Email.OutOfOffice.internalReply|Unknown|Out-of-office internal reply.|
|Account.Email.OutOfOffice.externalReply|Unknown|Out-of-office external reply.|
|Account.Email.OutOfOffice.mailbox|Unknown|Out-of-office mailbox.|


#### Examples

```
!ews-get-out-of-office target-mailbox=test@demistodev.onmicrosoft.com
```

###### Human Readable Output

>|end|externalAudience|mailbox|start|state|
>|--- |--- |--- |--- |--- |
>|2019-08-12T13:00:00Z|All|test@demistodev.onmicrosoft.com|2019-08-11T13:00:00Z|Disabled|

###### Context Example

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


</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-recover-messages</h3></summary>

### ews-recover-messages

Recovers messages that were soft-deleted.

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|message-ids|A CSV list of message IDs. Run the py-ews-delete-items command to retrieve the message IDs|Required|
|target-folder-path|The folder path to recover the messages to.|Required|
|target-mailbox|The mailbox in which the messages found. If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox.|Optional|
|is-public|Whether the target folder is a public folder.|Optional|

#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.itemId|Unknown|The item ID of the recovered item.|
|EWS.Items.messageId|Unknown|The message ID of the recovered item.|
|EWS.Items.action|Unknown|The action taken on the item. The value will be 'recovered'.|

#### Examples

```
!ews-recover-messages message-ids=<DFVDFmvsCSCS.com> target-folder-path=Moving target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

>|action|itemId|messageId|
>|--- |--- |--- |
>|recovered|AAVCSVS1hN2NkLThmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed33wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVyFtlscfxxd/AAA=||

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


</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-create-folder</h3></summary>

### ews-create-folder

Creates a new folder in a specified mailbox.

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|new-folder-name|The name of the new folder.|Required|
|folder-path|Path to locate the new folder. Exchange folder ID is also supported.|Required|
|target-mailbox|The mailbox in which to create the folder.|Optional|

#### Outputs

There is no context output for this command.


#### Examples

```
!ews-create-folder folder-path=Inbox new-folder-name="Created Folder" target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output
>
> Folder Inbox\Created Folder created successfully


</details>

<details>
<summary><h3 style={{display: 'inline'}}>ews-mark-item-as-junk</h3></summary>

### ews-mark-item-as-junk

Marks an item as junk. This is used to block an email address (meaning all future emails from this sender will be sent to the junk folder). For more information, see the [Microsoft documentation](https://msdn.microsoft.com/en-us/library/office/dn481311(v=exchg.150).aspx).

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id|The item ID to mark as junk.|Required|
|move-items|Whether to move the item from the original folder to the junk folder.|Optional|
|target-mailbox|If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox.|Optional|

#### Outputs

There is no context output for this command.

#### Examples

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

</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-find-folders</h3></summary>

### ews-find-folders

Retrieves information for the folders of the specified mailbox. Only folders with read permissions will be returned. Your visual folders on the mailbox, such as "Inbox", are under the folder "Top of Information Store".

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|target-mailbox|The mailbox on which to apply the command.|Optional|
|is-public|Whether to find public folders.|Optional|

#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Folders.name|string|Folder name.|
|EWS.Folders.id|string|Folder ID.|
|EWS.Folders.totalCount|Unknown|Number of items in the folder.|
|EWS.Folders.unreadCount|number|Number of unread items in the folder.|
|EWS.Folders.changeKey|number|Folder change key.|
|EWS.Folders.childrenFolderCount|number|Number of sub-folders.|


#### Examples

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

</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-get-items-from-folder</h3></summary>

### ews-get-items-from-folder

Retrieves items from a specified folder in a mailbox. The items are ordered by the item created time. Most recent is first.

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|folder-path|The folder path from which to get the items.|Required|
|limit|Maximum number of items to return.|Optional|
|target-mailbox|The mailbox on which to apply the command.|Optional|
|is-public|Whether the folder is a public folder. Default is 'False'.|Optional|
|get-internal-items|If the email item contains another email as an attachment (EML or MSG file), whether to retrieve the EML/MSG file attachment. Can be "yes" or "no". Default is "no".|Optional|


#### Outputs

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
|EWS.Items.isRead|String|The read status of the email.|
|EWS.Items.categories|String|Categories of the email.|

#### Examples

```
!ews-get-items-from-folder folder-path=Test target-mailbox=test@demistodev.onmicrosoft.com limit=1
```

##### Human Readable Output

>|sender|subject|hasAttachments|datetimeReceived|receivedBy|author|toRecipients|itemId|
>|--- |--- |--- |--- |--- |--- |--- |--- |
>|test2@demistodev.onmicrosoft.com|Get Attachment Email|true|2019-08-11T10:57:37Z|test@demistodev.onmicrosoft.com|test2@demistodev.onmicrosoft.com|test@demistodev.onmicrosoft.com|AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAA=|

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

</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-get-items</h3></summary>

### ews-get-items

Retrieves items by item ID.

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-ids|A CSV list of item IDs.|Required|
|target-mailbox|The mailbox on which to run the command on.|Optional|


#### Outputs

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
|EWS.Items.categories|String|Categories of the email.|
|Email.CC|String|Email addresses CC'ed to the email.|
|Email.BCC|String|Email addresses BCC'ed to the email.|
|Email.To|String|The recipient of the email.|
|Email.From|String|The sender of the email.|
|Email.Subject|String|The subject of the email.|
|Email.Text|String|The plain-text version of the email.|
|Email.HTML|String|The HTML version of the email.|
|Email.HeadersMap|String|The headers of the email.|

#### Examples

```
!ews-get-items item-ids=AAMkADQ0NmFkODFkLWQ4MDEtNDFDFZjNTMxNwBGAAAAAAA4kxhFFAfxw+jAAA= target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

```
Identical outputs to `ews-get-items-from-folder` command.
```

</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-move-item-between-mailboxes</h3></summary>

### ews-move-item-between-mailboxes

Moves an item from one mailbox to a different mailbox.

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-id|The item ID to move.|Required|
|destination-folder-path|The folder in the destination mailbox to which to move the item. You can specify a complex path, for example, "Inbox\Phishing".|Required|
|destination-mailbox|The mailbox to which to move the item.|Required|
|source-mailbox|The mailbox from which to move the item (conventionally called the "target-mailbox", the target mailbox on which to run the command).|Optional|
|is-public|Whether the destination folder is a public folder. Default is "False".|Optional|

#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.movedToMailbox|string|The mailbox to which the item was moved.|
|EWS.Items.movedToFolder|string|The folder to which the item was moved.|
|EWS.Items.action|string|The action taken on the item. The value will be "moved".|

#### Examples

```
!ews-move-item-between-mailboxes item-id=AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NFSFSyNzBkNABGAAAAAACYCKjWAjq/zTrN6vWSzK4OWAAK2ISFSA= destination-folder-path=Moving destination-mailbox=test@demistodev.onmicrosoft.com source-mailbox=test2@demistodev.onmicrosoft.com
```

##### Human Readable Output

>Item was moved successfully.

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

</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-get-folder</h3></summary>

### ews-get-folder

Retrieves a single folder.

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

If Exchange is configured with an international flavor, `Inbox` will be named according to the configured language.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|target-mailbox|The mailbox on which to apply the search.|Optional|
|folder-path|The path of the folder to retrieve. If empty, will retrieve the folder "AllItems".|Optional|
|is-public|Whether the folder is a public folder. Default is "False".|Optional|

#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Folders.id|string|Folder ID.|
|EWS.Folders.name|string|Folder name.|
|EWS.Folders.changeKey|string|Folder change key.|
|EWS.Folders.totalCount|number|Total number of emails in the folder.|
|EWS.Folders.childrenFolderCount|number|Number of sub-folders.|
|EWS.Folders.unreadCount|number|Number of unread emails in the folder.|

#### Examples

```
!ews-get-folder folder-path=demistoEmail target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

>|changeKey|childrenFolderCount|id|name|totalCount|unreadCount|
>|--- |--- |--- |--- |--- |--- |
>|***yFtCdJSH|0|AAMkADQ0NmFkODFkLWQ4MDEtNDE4Mi1hN2NlsjflsjfSF=|demistoEmail|1|0|

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

</details>


<details>
<summary><h3 style={{display: 'inline'}}>ews-expand-group</h3></summary>

### ews-expand-group

Expands a distribution list to display all members. By default, expands only the first layer of the distribution list. If recursive-expansion is "True", the command expands nested distribution lists and returns all members.

#### Permissions

Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|email-address|Email address of the group to expand.|Required|
|recursive-expansion|Whether to enable recursive expansion. Default is "False".|Optional|

#### Outputs

There is no context output for this command.

#### Examples

```
!ews-expand-group email-address="TestPublic" recursive-expansion="False"
```

##### Human Readable Output

>|displayName|mailbox|mailboxType|
>|--- |--- |--- |
>|John Wick|john@wick.com|Mailbox|

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

</details>

<details>
<summary><h3 style={{display: 'inline'}}>ews-mark-items-as-read</h3></summary>

### ews-mark-items-as-read

Marks items as read or unread.

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|item-ids|A CSV list of item IDs.|Required|
|operation|How to mark the item. Can be "read" or "unread". Default is "read".|Optional|
|target-mailbox|The mailbox on which to run the command. If empty, the command will be applied on the default mailbox.|Optional|

#### Outputs

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|EWS.Items.action|String|The action that was performed on the item.|
|EWS.Items.itemId|String|The ID of the item.|
|EWS.Items.messageId|String|The message ID of the item.|


#### Examples

```
!ews-mark-items-as-read item-ids=AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA= operation=read target-mailbox=test@demistodev.onmicrosoft.com
```

##### Human Readable Output

>|action|itemId|messageId|
>|--- |--- |--- |
>|marked-as-read|AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA=||

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

</details>

<details>
<summary><h3 style={{display: 'inline'}}>send-mail</h3></summary>

### send-mail

***
Sends an email.

#### Base Command

`send-mail`

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

When sending the email to an Outlook account, Outlook UI fails to display custom headers. This does not happen when sending to a Gmail account.

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Email addresses for the 'To' field. Supports comma-separated values. | Optional |
| cc | Email addresses for the 'Cc' field. Supports comma-separated values. | Optional |
| bcc | Email addresses for the 'Bcc' field. Supports comma-separated values. | Optional |
| subject | Subject for the email to be sent. | Optional | 
| body | The contents (body) of the email to be sent in plain text. | Optional | 
| htmlBody | The contents (body) of the email to be sent in HTML format. | Optional |
| attachIDs | A comma-separated list of War Room entry IDs that contain the files to attach to the email. | Optional |
| attachNames | A comma-separated list to rename file names of corresponding attachment IDs. For example, rename the first two files - attachNames=file_name1,file_name2. rename first and third file - attachNames=file_name1,,file_name3. | Optional |
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
| handle_inline_image | Whether to handle inline images in the HTML body. When set to 'True', inline images will be extracted from the HTML and attached to the email as an inline attachment object. Note that in some cases, attaching the image as an object may cause the image to disappear when replying to the email. Additionally, sending the image in the html body as base64 data (inline image) may cause the image to disappear if the image is too large or recognized as malicious and subsequently deleted. Possible values are: True, False. Default is True. | Optional |

#### Context Output

There is no context output for this command.

#### Examples

```
!send-mail to=demisto@demisto.onmicrosoft.com subject=some_subject body=some_text attachIDs=110@457,116@457 htmlBody="<html><body>Hello <b>World</b></body></html>" additionalHeader="some_header_name=some_header_value" transientFile=some_file.txt transientFileContent="Some file content"
```

##### Human Readable Output

>Mail sent successfully

</details>

<details>
<summary><h3 style={{display: 'inline'}}>ews-get-items-as-eml</h3></summary>

### ews-get-items-as-eml

Retrieves items by item ID and uploads its content as an EML file.

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.

#### Limitations

No known limitations.

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item-id | The item ID of item to upload as and EML file. | Required |
| target-mailbox | The mailbox in which this email was found. If empty, the default mailbox is used. Otherwise the user might require impersonation rights to this mailbox. | Optional |

#### Outputs

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

#### Examples
>
> ``

</details>

<details>
<summary><h3 style={{display: 'inline'}}>reply-mail</h3></summary>

### reply-mail

Reply to an email

#### Permissions

Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the `ApplicationImpersonation` role.


#### Limitations

No known limitations.

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inReplyTo | ID of the item to reply to. | Required |
| to | A comma-separated list of email addresses for the 'to' field. | Required |
| cc | A comma-separated list of email addresses for the 'cc' field. | Optional |
| bcc | A comma-separated list of email addresses for the 'bcc' field. | Optional |
| subject | Subject for the email to be sent. | Optional |
| body | The contents (body) of the email to send. | Optional |
| htmlBody | HTML formatted content (body) of the email to be sent. This argument overrides the "body" argument. | Optional |
| attachIDs | A comma-separated list of War Room entry IDs that contain files, and are used to attach files to the outgoing email. For example: attachIDs=15@8,19@8. | Optional |
| attachNames | A comma-separated list of names of attachments to send. Should be the same number of elements as attachIDs. | Optional |
| attachCIDs | A comma-separated list of CIDs to embed attachments within the email itself. | Optional |


#### Outputs

There is no context output for this command.


#### Examples

```!reply-mail item_id=AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq/zTrN6vWSzK4OWAAAAAAEMAADrxRwRjq/zTrN6vWSzK4OWAAPYQGFeAAA= body=hello subject=hi to="avishai@demistodev.onmicrosoft.com"```

##### Human Readable Output

##### Sent email

>|attachments|from|subject|to|
>|---|---|---|---|
>|  | avishai@demistodev.onmicrosoft.com | hi | avishai@demistodev.onmicrosoft.com |


</details>

<details>
<summary><h3 style={{display: 'inline'}}>ews-auth-reset</h3></summary>

### ews-auth-reset

Run this command if for some reason you need to rerun the authentication process.

#### Permissions

No additional permissions are needed.

#### Limitations

No known limitations.

#### Inputs

There is no input for this command.


#### Outputs

There is no context output for this command.




</details>


## Troubleshooting

<details><summary><h3 style={{display: 'inline'}}>Instance Configuration </h3></summary> No troubleshooting found. </details>

<details><summary><h3 style={{display: 'inline'}}> Fetch command </h3></summary>

* If incidents are not being fetched, verify that no `pre-process` rule is configured that might filter some incidents out.
* "address parts cannot contain CR or LF" error message in the logs means a corrupted email might have failed the process. In order to resolve this, you might need to remove the email from the folder being fetched. Contact Support Team if you believe the email is not corrupted.

</details>

<details><summary><h3 style={{display: 'inline'}}> Fetching Incidents crash due to unparsable emails </h3></summary>
If you find that your fetch incidents command is unable to parse a specific invalid email due to various parsing issues, you can follow these steps:

1. In the instance configuration, navigate to the *Collect* section and click on *Advanced Settings*.
2. Check the box labeled *Skip unparsable emails during fetch incidents*.

By enabling this option, the integration can catch and skip unparsable emails without causing the fetch incidents command to crash.
When this parameter is active, a message will appear in the "Fetch History" panel of the instance whenever an unparsable email is recognized and skipped.
This allows customers to be informed that a specific email was skipped and gives them the opportunity to open a support ticket if necessary.

</details>

<details><summary><h3 style={{display: 'inline'}}> General </h3></summary>

* ews-get-searchable-mailboxes:
When using the UPN parameter, the command ews-get-searchable-mailboxes runs correctly after assigning RBAC roles requested in the management role header as explained in the [Microsoft Documentation](https://learn.microsoft.com/en-us/Exchange/policy-and-compliance/ediscovery/assign-permissions?redirectedfrom=MSDN&view=exchserver-2019).

</details>
