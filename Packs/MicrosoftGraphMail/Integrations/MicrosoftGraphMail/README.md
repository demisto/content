Use the Microsoft Graph integration to let your applications get authorized access to a user's Outlook mail data in a personal or organization account.

## Authentication
For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).

### Required Permissions
* Mail.ReadWrite - Application
* User.Read - Application

### OData Usage
The OData parameter can be used to create different queries for the ***msgraph-mail-list-emails*** and ***msgraph-mail-get-email*** commands. Please see [OData Docs](https://docs.microsoft.com/en-us/graph/query-parameters) for detailed information.
Examples:
* ```!msgraph-mail-list-emails user_id=dev@demistodev.onmicrosoft.com odata="$select=from"```
* ```!msgraph-mail-list-emails user_id=dev@demistodev.onmicrosoft.com odata="$filter=from/emailAddress/address eq 'azure-noreply@microsoft.com'"```
* ```!msgraph-mail-list-emails user_id=dev@demistodev.onmicrosoft.com odata="$filter=sentDateTime gt 2020-03-25T09:35:23Z and sentDateTime lt 2020-03-25T12:04:47Z" ```

**NOTE:**
The query parameter '$filter' is not supported when using the 'search' parameter.

## Configure Microsoft Graph Mail on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MicrosoftGraphMail.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | The server URL. | True |
| auth_id | The ID (received from the admin consent - see the Detailed Instructions (?) section). | True |
| tenant_id | The token (received from the admin consent - see the Detailed Instructions (?) section). | True |
| enc_key | The Key (received from the admin consent - see the Detailed Instructions (?) section). | True |
| isFetch | The fetched incidents. | False |
| mailbox_to_fetch | The email address from which to fetch incidents (e.g. "example<span\>>@demisto.com"). | False |
| folder_to_fetch | The name of the folder from which to fetch incidents (supports Folder ID and sub-folders e.g. Inbox/Phishing). | False |
| first_fetch | The first fetched timestamp ((number) (time unit), e.g., 12 hours, 7 days). | False |
| fetch_limit | The maximum number of emails to pull per fetch. | False |
| insecure | Whether to trust any certificate (not secure). | False |
| proxy | Whether to use system proxy settings. | False |
| self_deployed | Whether to use a self deployed Azure Application. | False |
| incidentType | The incident type. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get properties of returned emails
***
Gets the properties of returned emails.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.ReadWrite (Application)
- User.Read

##### Base Command

`msgraph-mail-list-emails`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID from which to pull emails (can be principal ID (email address)). | Required | 
| folder_id |  The comma-separated list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box).  | Optional | 
| odata | An OData query. | Optional | 
| search | The term for which to search. This argument cannot contain reserved characters such as "!, $, #, @, etc". Click [here](https://tools.ietf.org/html/rfc3986#section-2.2) for further information. | Optional | 
| pages_to_pull | The number of pages of emails to return. The maximum is 10 emails per page. | Optional | 


##### Context Output

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
| MSGraphMail.Body | String | The content (body) of the email. | 
| MSGraphMail.Sender.Name | String | The name of the sender. | 
| MSGraphMail.Sender.Address | String | The email address of the sender. | 
| MSGraphMail.From.Name | String | The name of the user in the 'from' field of the email. | 
| MSGraphMail.From.Address | String | The email address of the user in the 'from' field of the email | 
| MSGraphMail.CCRecipients.Name | String | The names of the CC recipients. | 
| MSGraphMail.CCRecipients.Address | String | The email address of the user in the 'cc' field of the email. | 
| MSGraphMail.BCCRecipients.Name | String | The names of the users in the 'bcc' field of the email. | 
| MSGraphMail.BCCRecipients.Address | String | The email address of the user in the 'bcc' field of the email. | 
| MSGraphMail.ReplyTo.Name | String | The name in the 'replyTo' field of the email. | 
| MSGraphMail.ReplyTo.Address | String | The email address in the 'replyTo' field of the email. | 
| MSGraphMail.UserID | String | The ID of the user. | 


##### Command Example
```!msgraph-mail-list-emails user_id=dev@demistodev.onmicrosoft.com search="Demo" folder_id=inbox```

##### Context Example
```
{
    "MSGraphMail": [
        {
            "BCCRecipients": null,
            "CCRecipients": null,
            "Categories": [],
            "Created": "2020-03-29T09:56:37Z",
            "Flag": {
                "flagStatus": "notFlagged"
            },
            "From": {
                "Address": "dev@demistodev.onmicrosoft.com",
                "Name": "demisto dev"
            },
            "HasAttachments": true,
            "Headers": null,
            "ID": """",
            "Importance": "low",
            "IsDraft": false,
            "LastModifiedTime": "2020-03-29T09:56:37Z",
            "ReceivedTime": "2020-03-29T09:56:37Z",
            "ReplyTo": null,
            "SendTime": "2020-03-29T09:56:37Z",
            "Sender": {
                "Address": "dev@demistodev.onmicrosoft.com",
                "Name": "demisto dev"
            },
            "Subject": "Demo test send mail",
            "UserID": "dev@demistodev.onmicrosoft.com"
        },
    ]
}
```

##### Human Readable Output
##### ### Total of 7 of mails received
|Subject|From|SendTime|ID|
|---|---|---|---|
| Demo test send mail | Name: demisto dev, Address: dev<span\>>@demistodev.onmicrosoft.com | 2020-03-29T09:56:37Z | AQMkADY0ZjMxZmMyLWU3MjgtNDNiOS04ZDZmLTYxZDVkYzk1MTg5MwBGAAADbTQIjNRTu0OcDJw7xPpreQcAdQ8OJfUvxEa-MxMBZHrT7QAAAgEJAAAAdQ8OJfUvxEa-MxMBZHrT7QACY4VISQBBBA== |
| RE: Demo test | Name: demisto dev, Address: dev<span\>>@demistodev.onmicrosoft.com | 2020-03-29T09:56:18Z | AQMkADY0ZjMxZmMyLWU3MjgtNDNiOS04ZDZmLTYxZDVkYzk1MTg5MwBGAAADbTQIjNRTu0OcDJw7xPpreQcAdQ8OJfUvxEa-MxMBZHrT7QAAAgEJAAAAdQ8OJfUvxEa-MxMBZHrT7QACY4VISQCCAA== |
| Demo test send mail | Name: demisto dev, Address: dev<span\>>@demistodev.onmicrosoft.com | 2020-03-29T09:52:59Z | AQMkADY0ZjMxZmMyLWU3MjgtNDNiOS04ZDZmLTYxZDVkYzk1MTg5MwBGAAADbTQIjNRTu0OcDJw7xPpreQcAdQ8OJfUvxEa-MxMBZHrT7QAAAgEJDCAAdQ8OJfUvxEa-MxMBZHrT7QACY4VISQAAAA== |
| RE: Demo test | Name: demisto dev, Address: dev<span\>>@demistodev.onmicrosoft.com | 2020-03-29T09:52:41Z | AQMkADY0ZjMxZmMyLWU3MjgtNDNiOS04ZDZmLTYxZDVkYzk1MTg5MwBGAAADbTQIjNRTu0OcDJw7xPpreQcAdQ8OJfUvxEa-MxMBZHrT7QAAAgEJAAAAdQ8OJfUvxEk-MxMBZHrT7QACY4VISQAAAA== |
| RE: Demo test | Name: demisto dev, Address: dev<span\>>@demistodev.onmicrosoft.com | 2020-03-29T09:51:06Z | AAAkADY0ZjMxZmMyLWU3MjgtNDNiOS04ZDZmLTYxZDVkYzk1MTg5MwBGAAADbTQIjNRTu0OcDJw7xPpreQcAdQ8OJfUvxEa-MxMBZHrT7QAAAgEJAAAAdQ8OJfUvxEa-MxMBZHrT7QACY4VISQAAAA== |
| Demo test send mail | Name: demisto dev, Address: dev<span\>>@demistodev.onmicrosoft.com | 2020-03-29T09:06:54Z | ABKkADY0ZjMxZmMyLWU3MjgtNDNiOS04ZDZmLTYxZDVkYzk1MTg5MwBGAAADbTQIjNRTu0OcDJw7xPpreQcAdQ8OJfUvxEa-MxMBZHrT7QAAAgEJAAAAdQ8OJfUvxEa-MxMBZHrT7QACY4VISQAAAA== |
| Demo test | Name: demisto dev, Address: dev<span\>>@demistodev.onmicrosoft.com | 2020-03-26T09:21:14Z | AQKkADY0ZjMxZmMyLWU3MjgtNDNiOS04ZDZmLTYxZDVkYzk1MTg5MwBGAAADbTQIjNRTu0OcDJw7xPpreQcAdQ8OJfUvxEa-MxMBZHrT7QAAAgEJAAAAdQ8OJfUvxEa-MxMBZHrT7QACY4VISQAAAA== |



### Get the properties of a single email
***
Returns the properties of an email.

##### Required Permissions
**The following permissions are required for this command:**
- User.Read

##### Base Command

`msgraph-mail-get-email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<span\>>@example.com). | Required | 
| message_id | The message ID. This could be extracted from - msgraph-mail-list-emails command results. | Required | 
| folder_id | The folder ID. | Optional | 
| odata | The OData. | Optional | 
| get_body | Whether to return the message body. Can be "true" or "false". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.ID | String | The ID of the email. | 
| MSGraphMail.Created | Date | The time the email was created. | 
| MSGraphMail.LastModifiedTime | Date | The time the email was last modified. | 
| MSGraphMail.ReceivedTime | Date | The time the email was received. | 
| MSGraphMail.SendTime | Date | The time the email was sent. | 
| MSGraphMail.Categories | String | The categories of the email. | 
| MSGraphMail.HasAttachments | Boolean | Whether the email has attachments. | 
| MSGraphMail.Subject | String | The subject of the email. | 
| MSGraphMail.IsDraft | Boolean | Whether the email is a draft. | 
| MSGraphMail.Body | String | The content (body) of the email. | 
| MSGraphMail.Sender.Name | String | The name of the sender. | 
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


##### Command Example
```!msgraph-mail-get-email message_id="message_id" user_id=dev@demistodev.onmicrosoft.com```

##### Context Example
```
{
    "MSGraphMail": {
        "BCCRecipients": null,
        "CCRecipients": null,
        "Categories": [],
        "Created": "2020-03-26T09:21:15Z",
        "Flag": {
            "flagStatus": "notFlagged"
        },
        "From": {
            "Address": "dev@demistodev.onmicrosoft.com",
            "Name": "demisto dev"
        },
        "HasAttachments": false,
        "Headers": null,
        "ID": """",
        "Importance": "low",
        "IsDraft": false,
        "LastModifiedTime": "2020-03-29T09:56:18Z",
        "ReceivedTime": "2020-03-26T09:21:15Z",
        "ReplyTo": null,
        "SendTime": "2020-03-26T09:21:14Z",
        "Sender": {
            "Address": "dev@demistodev.onmicrosoft.com",
            "Name": "demisto dev"
        },
        "Subject": "Demo test",
        "UserID": "dev@demistodev.onmicrosoft.com"
    }
}
```

##### Human Readable Output
##### Results for message ID ""
|ID|Subject|SendTime|Sender|From|HasAttachments|Body|
|---|---|---|---|---|---|---|
| "" | Demo test | 2020-03-26T09:21:14Z | Name: demisto dev, Address: dev<span\>>@demistodev.onmicrosoft.com | Name: demisto dev, Address: dev<span\>>@demistodev.onmicrosoft.com | false |  |

#### OData Usage
The OData parameter can be used to create different queries. Please see [OData Docs](https://docs.microsoft.com/en-us/graph/query-parameters) for detailed information.
Example:
* ```!msgraph-mail-get-email user_id=dev@demistodev.onmicrosoft.com message_id="message_id" odata="$select=from"```


##### Required Permissions
**The following permissions are required for this command:**
- Mail.ReadWrite (Application)

### Delete an email
***
Deletes an email.


##### Base Command

`msgraph-mail-delete-email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<span\>>@example.com). | Required | 
| message_id | The message ID. | Required | 
| folder_id | The comma-separated list of folder IDs. For example, "mailFolders,childFolders,childFolders". | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!msgraph-mail-delete-email user_id=dev@demistodev.onmicrosoft.com message_id="message_id"```

##### Context Example
```
{}
```

##### Human Readable Output
##### Message has been deleted successfully
|Message ID|User ID|
|---|---|
| "" | dev<span\>>@demistodev.onmicrosoft.com |


### List attachments of an email
***
Lists all of the attachments of a given email.

##### Required Permissions
**The following permissions are required for this command:**
- User.Read
    
##### Base Command

`msgraph-mail-list-attachments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<span\>>@example.com). | Required | 
| message_id | The message ID. | Required | 
| folder_id |  The comma-separated list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box).  | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMailAttachment.ID | String | The email ID. | 
| MSGraphMailAttachment.Attachment.ID | String | The ID of the attachment. | 
| MSGraphMailAttachment.Attachment.Name | String | The name of the attachment. | 
| MSGraphMailAttachment.Attachment.Type | String | The attachment type. | 
| MSGraphMailAttachment.UserID | String | The ID of the user. | 


##### Command Example
```!msgraph-mail-list-attachments message_id="message_id" user_id=dev@demistodev.onmicrosoft.com```

##### Context Example
```
{
    "MSGraphMailAttachment": {
        "Attachment": [
            {
                "ID": """",
                "Name": "test_attachment",
                "Type": "application/octet-stream"
            }
        ],
        "ID": """",
        "UserID": "dev@demistodev.onmicrosoft.com"
    }
}
```

##### Human Readable Output
##### Total of 1 attachments found in message "" from user dev<span\>>@demistodev.onmicrosoft.com
|File names|
|---|
| test_attachment |


### Get an attachment from an email
***
Gets an attachment from the email.

##### Required Permissions
**The following permissions are required for this command:**
- User.Read

##### Base Command

`msgraph-mail-get-attachment`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<span\>>@example.com). | Required | 
| message_id | The message ID. | Required | 
| folder_id | The comma-separated list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box). | Optional | 
| attachment_id | The ID of the attachment. | Required | 


##### Context Output

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


##### Command Example
```!msgraph-mail-get-attachment attachment_id="" message_id="message_id" user_id=dev@demistodev.onmicrosoft.com```

##### Context Example
```
{
    "File": {
        "EntryID": "8017@f6e9c46f-e2e9-446f-8cd9-909bd5f72dbf",
        "Info": "image/jpeg",
        "MD5": "009a889d2f93dceeb9bf0df0870e8f58",
        "Name": "test_attachment",
        "SHA1": "3cb49da95c7c1acb80496329636cc14b07fc82fb",
        "SHA256": "9e930d4a9fc01e91729f3d6acfa2d793cbf6db5a4b48ae2cf9d8c0aac57cc998",
        "SHA512": """",
        "SSDeep": """",
        "Size": 978210,
        "Type": "JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=12, height=1599, bps=0, PhotometricIntepretation=RGB, orientation=upper-left, width=1200], progressive, precision 8, 1200x1599, frames 3"
    }
}
```

##### Human Readable Output
There is no Human Readable Output.

### Get the mail folder list under the root folder
***
Returns the mail folder list directly under the root folder.

##### Required Permissions
**The following permissions are required for this command:**
* Mail.ReadWrite (Application)
* User.Read
    
##### Base Command

`msgraph-mail-list-folders`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<span\>>@example.com). | Required | 
| limit | The maximum number of mail folder lists to return. The default is 20. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | Number | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | String | The folder display name. | 
| MSGraphMail.Folders.ID | String | The target folder ID. | 
| MSGraphMail.Folders.ParentFolderID | String | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | Number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | Number | The number of unread emails in the folder. | 


##### Command Example
```!msgraph-mail-list-folders user_id=dev@demistodev.onmicrosoft.com limit=2```

##### Context Example
```
{
    "MSGraphMail": {
        "Folders": [
            {
                "ChildFolderCount": 0,
                "DisplayName": "Archive",
                "ID": """",
                "ParentFolderID": """",
                "TotalItemCount": 0,
                "UnreadItemCount": 0
            },
            {
                "ChildFolderCount": 1,
                "DisplayName": "Conversation History",
                "ID": """",
                "ParentFolderID": """",
                "TotalItemCount": 0,
                "UnreadItemCount": 0
            }
        ]
    }
}
```

##### Human Readable Output

##### Mail Folder collection under root folder for user dev<span\>>@demistodev.onmicrosoft.com

|ChildFolderCount|DisplayName|ID|ParentFolderID|TotalItemCount|UnreadItemCount|
|---|---|---|---|---|---|
| 0 | Archive | "" | "" | 0 | 0 |
| 1 | Conversation History | "" | "" | 0 | 0 |


### Get the folder list for a folder
***
Returns the folder list under the specified folder.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.ReadWrite (Application)
- User.Read

##### Base Command

`msgraph-mail-list-child-folders`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<Span\>@example.com). | Required | 
| parent_folder_id | The ID of the parent folder. | Required | 
| limit | The maximum number of mail folder lists to return. The default is 20. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | Number | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | String | The folder display name. | 
| MSGraphMail.Folders.ID | String | The folder ID. | 
| MSGraphMail.Folders.ParentFolderID | String | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | Number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | Number | The number of unread email messages in the folder. | 


##### Command Example
```!msgraph-mail-list-child-folders user_id=dev@demistodev.onmicrosoft.com parent_folder_id=inbox```

##### Context Example
```
{
    "MSGraphMail": {
        "Folders": [
            {
                "ChildFolderCount": 0,
                "DisplayName": "child_folder",
                "ID": ",
                "ParentFolderID": """",
                "TotalItemCount": 0,
                "UnreadItemCount": 0
            },
            {
                "ChildFolderCount": 0,
                "DisplayName": "new_test",
                "ID": """",
                "ParentFolderID": """",
                "TotalItemCount": 0,
                "UnreadItemCount": 0
            }
        ]
    }
}
```

##### Human Readable Output
##### Mail Folder collection under inbox folder for user dev<span\>>@demistodev.onmicrosoft.com
|ChildFolderCount|DisplayName|ID|ParentFolderID|TotalItemCount|UnreadItemCount|
|---|---|---|---|---|---|
| 0 | child_folder | "" | "" | 0 | 0 |
| 0 | new_test | "" | "" | 0 | 0 |


### Create a new child folder
***
Creates a new folder under the specified folder (parent).

##### Required Permissions
**The following permissions are required for this command:**
- Mail.ReadWrite (Application)
    
##### Base Command

`msgraph-mail-create-folder`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<span\>>@example.com). | Required | 
| new_folder_name | The display name of the new folder. | Required | 
| parent_folder_id | The ID of the parent folder under which to create a new folder. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | Number | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | String | The folder display name. | 
| MSGraphMail.Folders.ID | String | The folder ID. | 
| MSGraphMail.Folders.ParentFolderID | String | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | Number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | Number | The number of unread email messages in the folder. | 


##### Command Example
```!msgraph-mail-create-folder user_id=dev@demistodev.onmicrosoft.com new_folder_name="Testing"```

##### Context Example
```
{
    "MSGraphMail": {
        "Folders": {
            "ChildFolderCount": 0,
            "DisplayName": "Testing",
            "ID": """",
            "ParentFolderID": """",
            "TotalItemCount": 0,
            "UnreadItemCount": 0
        }
    }
}
```

##### Human Readable Output
##### Mail folder was created with display name: Testing
|ChildFolderCount|DisplayName|ID|ParentFolderID|TotalItemCount|UnreadItemCount|
|---|---|---|---|---|---|
| 0 | Testing | "" | "" | 0 | 0 |



### Update a folder's properties
***
Updates the properties of the specified folder.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.ReadWrite (Application)
    
##### Base Command

`msgraph-mail-update-folder`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<span\>>@example.com). | Required | 
| folder_id | The ID of the folder to update. | Required | 
| new_display_name | The mail folder display name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.Folders.ChildFolderCount | String | The number of child folders. | 
| MSGraphMail.Folders.DisplayName | String | The folder display name. | 
| MSGraphMail.Folders.ID | String | The folder ID. | 
| MSGraphMail.Folders.ParentFolderID | String | The parent folder ID. | 
| MSGraphMail.Folders.TotalItemCount | Number | The total number of email messages in the folder. | 
| MSGraphMail.Folders.UnreadItemCount | Number | The unread emails count inside the folder. | 


##### Command Example
```!msgraph-mail-update-folder user_id=dev@demistodev.onmicrosoft.com folder_id="folder_id" new_display_name="new_test"```

##### Context Example
```
{
    "MSGraphMail": {
        "Folders": {
            "ChildFolderCount": 0,
            "DisplayName": "new_test",
            "ID": """",
            "ParentFolderID": """",
            "TotalItemCount": 0,
            "UnreadItemCount": 0
        }
    }
}
```

##### Human Readable Output
##### Mail folder "" was updated with display name: new_test
|ChildFolderCount|DisplayName|ID|ParentFolderID|TotalItemCount|UnreadItemCount|
|---|---|---|---|---|---|
| 0 | new_test | "" | "" | 0 | 0 |


### Delete a folder
***
Deletes the specified mail folder.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.ReadWrite (Application)
    
##### Base Command

`msgraph-mail-delete-folder`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<Span\>@example.com). | Required | 
| folder_id | The ID of the folder to delete. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!msgraph-mail-delete-folder user_id=dev@demistodev.onmicrosoft.com folder_id="folder_id"```

##### Context Example
```
{}
```

##### Human Readable Output
The folder "" was deleted successfully


### Move a message to a different folder
***
Moves a message to a different folder.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.ReadWrite (Application)
    
##### Base Command

`msgraph-mail-move-email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The message ID. | Required | 
| destination_folder_id | The ID of the destination folder. | Required | 
| user_id | The user ID or principal ID (usually an email address in the format someuser<span\>>@example.com). | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.MovedEmails.DestinationFolderID | String | The folder where the email message was moved to. | 
| MSGraphMail.MovedEmails.ID | String | The new ID of the moved email message. | 
| MSGraphMail.MovedEmails.UserID | String | The user ID. | 


##### Context Example
```
{
    "MSGraphMail": {
        "MovedEmails": {
            "DestinationFolderID": "inbox",
            "ID": """",
            "UserID": "dev@demistodev.onmicrosoft.com"
        }
    }
}
```

##### Human Readable Output
##### The email was moved successfully. Updated email data:
|DestinationFolderID|ID|UserID|
|---|---|---|
| inbox | "" | dev<span\>>@demistodev.onmicrosoft.com |



### Get an email message by ID and upload the content
***
Retrieves an email message by message ID and uploads the content as an EML file.

##### Required Permissions
**The following permissions are required for this command:**
- User.Read

##### Base Command

`msgraph-mail-get-email-as-eml`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID or principal ID (usually an email address in the format someuser<span\>>@example.com). | Required | 
| message_id | The message ID. | Required | 


##### Context Output

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


##### Command Example
```!msgraph-mail-get-email-as-eml message_id="message_id" user_id=dev@demistodev.onmicrosoft.com```

##### Context Example
```
{
    "File": {
        "EntryID": "8025@f6e9c46f-e2e9-446f-8cd9-909bd5f72dbf",
        "Extension": "eml",
        "Info": "message/rfc822",
        "MD5": "5f32dc60c6f4dc7b01b4aa85a12459d9",
        "Name": """",
        "SHA1": "0320147ba32722549e810d2ecd5300b95a101bf6",
        "SHA256": "6476ede07246902ad34118df90ca8b590a006ffbd3dd142046a4cf81d2dde30d",
        "SHA512": "efa9cd6f787a24a31a9479366d2b6ac73a42e3bd7594933615a2cf659790dcbe9c3120740eb96fa8405e888a077d55745c3797999582d50f237ca2d4964a8547",
        "SSDeep": """",
        "Size": 2119,
        "Type": "RFC 822 mail text, ASCII text, with very long lines, with CRLF line terminators"
    }
}
```

##### Human Readable Output
There is No Human Readable Output.

### Create a draft message in a user's mailbox
***
Creates a draft message in the specified user's mailbox.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.ReadWrite (Application)

##### Base Command

`msgraph-mail-create-draft`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | The comma-separated list of email addresses for the 'to' field. | Optional | 
| cc | The comma-separated list of email addresses for the 'cc' field. | Optional | 
| bcc | The comma-separated list of email addresses for the 'bcc' field. | Optional | 
| subject | The subject for the draft. | Required | 
| body | The contents (body) of the draft. | Optional | 
| bodyType | The body type of the email. Can be, "text", or "HTML". | Optional | 
| flag | The flag value that indicates the status of the draft. Can be, "notFlagged", "complete", or "flagged". | Optional | 
| importance | The importance of the draft. Can be, "Low", "Normal", or "High". | Optional | 
| headers | The comma-separated list of additional headers in the format, "headerName:headerValue". For example, "headerName1:headerValue1,headerName2:headerValue2". | Optional | 
| attachIDs | The comma-separated list of War Room entry IDs that contain files, which are used to attach files to the draft. For example, "attachIDs=15@8,19@8". | Optional | 
| attachNames | The comma-separated list of names of attachments to be displayed in the draft. Must be the same number of elements as attachIDs. | Optional | 
| attachCIDs | The comma-separated list of CIDs to embed attachments within the actual email. | Optional | 
| from | The email address from which the draft is created. | Required | 


##### Context Output

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


##### Command Example
```!msgraph-mail-create-draft from=dev@demistodev.onmicrosoft.com subject="This is a draft" body="This is a body" to=dev@demistodev.onmicrosoft.com```

##### Context Example
```
{
    "MicrosoftGraph": {
        "Draft": {
            "Bcc": [],
            "Body": "This is a body",
            "BodyType": "text",
            "Cc": [],
            "ConversationID": """",
            "CreatedTime": "2020-03-29T09:57:38Z",
            "From": "",
            "Headers": [],
            "ID": """",
            "Importance": "low",
            "IsDraft": true,
            "IsRead": true,
            "MessageID": "<AM6PR07MB44530DA96C2DF255705F30FD83CA0@AM6PR07MB4453.eurprd07.prod.outlook.com>",
            "ModifiedTime": "2020-03-29T09:57:38Z",
            "ReceivedTime": "2020-03-29T09:57:38Z",
            "Sender": "",
            "SentTime": "2020-03-29T09:57:38Z",
            "Subject": "This is a draft",
            "To": [
                "dev@demistodev.onmicrosoft.com"
            ]
        }
    }
}
```

##### Human Readable Output
##### Created draft with id: ""
|ID|From|Sender|To|Subject|Body|BodyType|Cc|Bcc|Headers|Importance|MessageID|ConversationID|CreatedTime|SentTime|ReceivedTime|ModifiedTime|IsDraft|IsRead|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| "" |  |  | dev<span\>>@demistodev.onmicrosoft.com | This is a draft | This is a body | text |  |  |  | low | <AM6PR07MB44530DA96C2DF255705F30FD83CA0@AM6PR07MB4453.eurprd07.prod.outlook.<span\>>com> | "" | 2020-03-29T09:57:38Z | 2020-03-29T09:57:38Z | 2020-03-29T09:57:38Z | 2020-03-29T09:57:38Z | true | true |


### Send an email
***
Sends an email using Microsoft Graph.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.Send (Application)

##### Base Command

`send-mail`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | The comma-separated list of email addresses for the 'to' field. | Optional | 
| cc | The comma-separated list of email addresses for the 'cc' field. | Optional | 
| bcc | The comma-separated list of email addresses for the 'bcc' field. | Optional | 
| subject | The subject of the email. | Required | 
| body | The contents (body) of the email. | Optional | 
| bodyType | The body type of the email. Can be, "text" or "HTML". | Optional | 
| flag | The flag value that indicates the status for the email. Can be, "notFlagged", "complete", or "flagged". | Optional | 
| importance | The importance of the email. Can be, "Low", "Normal", or "High". | Optional | 
| headers | The comma-separated list of additional headers in the format: "headerName:headerValue". For example, "headerName1:headerValue1,headerName2:headerValue2". | Optional | 
| attachIDs | The comma-separated list of War Room entry IDs that contain files, which are used to attach files for the email to send. For example, attachIDs=15@8,19@8. | Optional | 
| attachNames | The comma-separated list of names of attachments to display in the email to send. It must have the same number of elements as attachIDs. | Optional | 
| attachCIDs | The comma-separated list of CIDs to embed attachments within the actual email. | Optional | 
| from | The email address from which to send the email. | Optional | 


##### Context Output

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


##### Command Example
```!send-mail subject="Demo test send mail" from=dev@demistodev.onmicrosoft.com attachIDs="attach_id" to=dev@demistodev.onmicrosoft.com attachNames="test_attachment"```

##### Context Example
```
{
    "MicrosoftGraph": {
        "Email": {
            "body": {
                "content": "",
                "contentType": "text"
            },
            "flag": {
                "flagStatus": "notFlagged"
            },
            "importance": "Low",
            "subject": "Demo test send mail",
            "toRecipients": [
                "dev@demistodev.onmicrosoft.com"
            ]
        }
    }
}
```

##### Human Readable Output
##### Email was sent successfully.
|body|flag|importance|subject|toRecipients|
|---|---|---|---|---|
| content: contentType: text | flagStatus: notFlagged | Low | Demo test send mail | dev<span\>>@demistodev.onmicrosoft.com |


### Reply to a message
***
Replies to the recipients of a message.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.Send (Application)
    
##### Base Command

`msgraph-mail-reply-to`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ID | The ID of the message. | Required | 
| body | The comment of the replied message. | Required | 
| to | The comma-separated list of email addresses for the 'to' field. | Required | 
| from | The email address from which to reply. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!msgraph-mail-reply-to ID="mail_id" body="reply_body" from=dev@demistodev.onmicrosoft.com to=dev@demistodev.onmicrosoft.com```

##### Context Example
```
{}
```

##### Human Readable Output
##### Replied to: dev<span\>>@demistodev.onmicrosoft.com with comment: reply_body

### Send a draft email
***
Sends a draft email using Microsoft Graph.

##### Required Permissions
**The following permissions are required for this command:**
- Mail.Send (Application)

##### Base Command

`msgraph-mail-send-draft`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| draft_id | The ID of the draft email. | Required | 
| from | The email address from which to send the draft. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!msgraph-mail-send-draft draft_id="draft_id" from=dev@demistodev.onmicrosoft.com```

##### Context Example
```
{}
```

##### Human Readable Output
##### Draft with: "" id was sent successfully.
