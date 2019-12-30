## Overview
---

Microsoft Graph lets your app get authorized access to a user’s Outlook mail data in a personal or organization account.

## Generate Authentication Parameters

To use this integration, you have to grant access to Demisto from Microsoft Graph.

1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for Microsoft Graph Mail.
3. Click **Add instance** to create and configure a new integration instance.
4. Click the question mark button in the upper-right corner and read the information, and click the link.
5. Click the **Start Authorization Process** button.
6. Log in with Microsoft admin user credentials.
7. Authorize Demisto application to access data.
8. When you are redirected, copy the parameter values, which you will need when configuring the integration instance in Demisto.
    * ID
    * Key
    * Token


## Configure Microsoft Graph Mail on Demisto
---
1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for MicrosoftGraphMail.
3. Click **Add instance** to create and configure a new integration instance.

    * **Name**: a textual name for the integration instance.**
    * **Server URL**
    * **ID you received from the admin consent**
    * **Key you received from the admin consent**
    * **Token you received from the admin consent**
    * **Trust any certificate (not secure)**
    * **Use system proxy**

4. Click Test to validate the URLs, token, and connection.

## Required Permissions

The following permissions are required for all commands:
* Mail.ReadWrite
* Directory.Read.All
* User.Read

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. msgraph-mail-list-emails
2. msgraph-mail-get-email
3. msgraph-mail-delete-email
4. msgraph-mail-list-attachments
5. msgraph-mail-get-attachment
6. msgraph-mail-list-folders
7. msgraph-mail-list-child-folders
8. msgraph-mail-create-folder
9. msgraph-mail-update-folder
10. msgraph-mail-delete-folder
11. msgraph-mail-move-email
12. msgraph-mail-get-email-as-eml
### 1. msgraph-mail-list-emails
---
Gets properties of mails.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-list-emails`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID from which to pull mails (can be principal ID (email address)). | Required | 
| folder_id |  A CSV list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box).  | Optional | 
| odata | Add an OData query. | Optional | 
| search | The term for which to search. This argument cannot contain reserved characters such as !, $, #, @, etc. For further information, see https://tools.ietf.org/html/rfc3986#section-2.2 | Optional | 
| pages_to_pull | The number of pages of emails to pull (maximum is 10 emails per page). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.ID | String | ID of email. | 
| MSGraphMail.Created | Date | Time of email creation. | 
| MSGraphMail.LastModifiedTime | Date | Time of last modified. | 
| MSGraphMail.ReceivedTime | Date | Time of email receiving. | 
| MSGraphMail.SendTime | Date | Time of sending email. | 
| MSGraphMail.Categories | String | Categories of email. | 
| MSGraphMail.HasAttachments | Boolean | If there're any attachments in the email | 
| MSGraphMail.Subject | String | Subject of email. | 
| MSGraphMail.IsDraft | Boolean | If the email is draft | 
| MSGraphMail.Body | String | Body of email | 
| MSGraphMail.Sender.Name | String | Name of sender | 
| MSGraphMail.Sender.Address | String | Email address of sender | 
| MSGraphMail.From.Name | String | Name of from | 
| MSGraphMail.From.Address | String | Email address of from | 
| MSGraphMail.CCRecipients.Name | String | Name of ccRecipients | 
| MSGraphMail.CCRecipients.Address | String | Email address of ccRecipients | 
| MSGraphMail.BCCRecipients.Name | String | Name of bccRecipients | 
| MSGraphMail.BCCRecipients.Address | String | Email address of bccRecipients | 
| MSGraphMail.ReplyTo.Name | String | Name of replyTo | 
| MSGraphMail.ReplyTo.Address | String | Email address of replyTo | 
| MSGraphMail.UserID | String | ID of user | 


##### Command Example
```!msgraph-mail-list-emails user_id=ex@example.com```

##### Context Example
``` 
{ 
   "MSGraphMail":[ 
      { 
         "CCRecipients":null,
         "From":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Sender":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Created":"2019-04-24T13:58:22Z",
         "HasAttachments":false,
         "ReceivedTime":"2019-04-24T13:58:23Z",
         "UserID":"or@example.com",
         "IsDraft":false,
         "ReplyTo":null,
         "BCCRecipients":null,
         "LastModifiedTime":"2019-04-24T13:58:24Z",
         "Subject":"jn",
         "ID":"AAMkADMzZWNjMjBNFPVsAqlO3YRKNFAAAF0dZUAAA=",
         "Categories":[ 

         ],
         "SendTime":"2019-04-24T13:58:22Z"
      },
      { 
         "CCRecipients":null,
         "From":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Sender":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Created":"2019-04-24T13:57:05Z",
         "HasAttachments":false,
         "ReceivedTime":"2019-04-24T13:57:06Z",
         "UserID":"ex@example.com",
         "IsDraft":false,
         "ReplyTo":null,
         "BCCRecipients":null,
         "LastModifiedTime":"2019-04-24T13:57:07Z",
         "Subject":"this is test 2",
         "ID":"AAMkADMzoON8u7AAAF0dZTAAA=",
         "Categories":[ 

         ],
         "SendTime":"2019-04-24T13:57:06Z"
      },
      { 
         "CCRecipients":null,
         "From":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Sender":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Created":"2019-04-24T13:54:50Z",
         "HasAttachments":false,
         "ReceivedTime":"2019-04-24T13:55:21Z",
         "UserID":"ex@example.com",
         "IsDraft":false,
         "ReplyTo":null,
         "BCCRecipients":null,
         "LastModifiedTime":"2019-04-24T13:55:22Z",
         "Subject":"this is a test",
         "ID":"AAMkADMzZ8u7AAAF0dZSAAA=",
         "Categories":[ 

         ],
         "SendTime":"2019-04-24T13:55:20Z"
      },
      { 
         "CCRecipients":null,
         "From":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Sender":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Created":"2019-04-24T13:47:57Z",
         "HasAttachments":false,
         "ReceivedTime":"2019-04-24T13:47:57Z",
         "UserID":"ex@example.com",
         "IsDraft":false,
         "ReplyTo":null,
         "BCCRecipients":null,
         "LastModifiedTime":"2019-04-24T13:47:58Z",
         "Subject":"dasdas",
         "ID":"AAMkADMzZWu7AAAF0Z_AAAA=",
         "Categories":[ 

         ],
         "SendTime":"2019-04-24T13:47:56Z"
      },
      { 
         "CCRecipients":null,
         "From":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Sender":{ 
            "Name":"Oren Zohar",
            "Address":"ex@example.com"
         },
         "Created":"2019-04-24T13:47:56Z",
         "HasAttachments":false,
         "ReceivedTime":"2019-04-24T13:47:57Z",
         "UserID":"ex@example.com",
         "IsDraft":false,
         "ReplyTo":null,
         "BCCRecipients":null,
         "LastModifiedTime":"2019-04-24T13:47:58Z",
         "Subject":"dasdas",
         "ID":"AAMkADMzZWNj3YRKNF6ZoON8u7AAAF0dZRAAA=",
         "Categories":[ 

         ],
         "SendTime":"2019-04-24T13:47:56Z"
      },
      { 
         "CCRecipients":null,
         "From":{ 
            "Name":"Bar Hochman",
            "Address":"se@example.com"
         },
         "Sender":{ 
            "Name":"Bar Hochman",
            "Address":"se@example.com"
         },
         "Created":"2019-04-24T06:42:01Z",
         "HasAttachments":true,
         "ReceivedTime":"2019-04-24T06:42:02Z",
         "UserID":"ex@example.com",
         "IsDraft":false,
         "ReplyTo":null,
         "BCCRecipients":null,
         "LastModifiedTime":"2019-04-24T06:48:35Z",
         "Subject":"\u05e7\u05d1\u05dc
\u05e7\u05d5\u05d1\u05e5 \u05e8\u05e0\u05d3\u05d5\u05de\u05d0\u05dc\u05d9",
         "ID":"AAMkADMzZWNjMjiMgBGAAAAAAC7AAAF0Z9-AAA=",
         "Categories":[ 

         ],
         "SendTime":"2019-04-24T06:41:56Z"
      }
   ]
}
```

##### Human Readable Output
### Total of 6 of mails received
Subject|From|SendTime|
|---|---|---|
|jn|Name: Or Zoh Address: ex@example.com|2019-04-24T13:58:22Z|
|this is test 2 |Name: Or Zoh Address: ex@example.com|2019-04-24T13:57:06Z|
|this is a test |Name: Or Zoh Address: ex@example.com|2019-04-24T13:55:20Z|
|dasdas|Name: Or Zoh Address: ex@example.com|2019-04-24T13:47:56Z|
|dasdas|Name: Or Zoh Address: ex@example.com|2019-04-24T13:47:56Z|
|Get a random file  |Name: Ba Hoc Address: se@example.com|2019-04-24T06:41:56Z|


### 2. msgraph-mail-get-email
---
Gets the properties of an email.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-get-email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (mostly email address). | Required | 
| message_id | Message ID. | Required | 
| folder_id | Folder ID. | Optional | 
| odata | OData. | Optional | 
| get_body | Whether the message body should be returned. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.ID | String | ID of email. | 
| MSGraphMail.Created | Date | Time of email creation. | 
| MSGraphMail.LastModifiedTime | Date | Time of last modified. | 
| MSGraphMail.ReceivedTime | Date | Time of email receiving. | 
| MSGraphMail.SendTime | Date | Time of sending email. | 
| MSGraphMail.Categories | String | Categories of email. | 
| MSGraphMail.HasAttachments | Boolean | If there're any attachments in the email | 
| MSGraphMail.Subject | String | Subject of email. | 
| MSGraphMail.IsDraft | Boolean | If the email is draft | 
| MSGraphMail.Body | String | Body of email | 
| MSGraphMail.Sender.Name | String | Name of sender | 
| MSGraphMail.Sender.Address | String | Email address of sender | 
| MSGraphMail.From.Name | String | Name of from | 
| MSGraphMail.From.Address | String | Email address of from | 
| MSGraphMail.CCRecipients.Name | String | Name of ccRecipients | 
| MSGraphMail.CCRecipients.Address | String | Email address of ccRecipients | 
| MSGraphMail.BCCRecipients.Name | String | Name of bccRecipients | 
| MSGraphMail.BCCRecipients.Address | String | Email address of bccRecipients | 
| MSGraphMail.ReplyTo.Name | String | Name of replyTo | 
| MSGraphMail.ReplyTo.Address | String | Email address of replyTo | 
| MSGraphMail.UserID | String | ID of user | 


##### Command Example
```!msgraph-mail-get-email message_id=AAMkADMzZWNjMgBGAAAAZoON8u7AAAF0Z9-AAA= user_id=ex@example.com get_body=true```

#### Context Example
```
{  
   "MSGraphMail":{  
      "Body":"<html>\r\n<head>\r\n<meta http-equiv=\"Content-Type\" 
  content=\"text/html; charset=utf-8\">\r\n<meta content=\"text/html; charset=utf-8\">\r\n<meta 
  name=\"Generator\" content=\"Microsoft Word 15 (filtered medium)\">\r\n<style>\r\n<!--\r\n@font-face\r\n\t{font-family:\"Cambria 
  Math\"}\r\n@font-face\r\n\t{font-family:Calibri}\r\np.MsoNormal, li.MsoNormal, 
  div.MsoNormal\r\n\t{margin:0cm;\r\n\tmargin-bottom:.0001pt;\r\n\tfont-size:12.0pt;\r\n\tfont-family:\"Calibri\",sans-serif}\r\na:link, 
  span.MsoHyperlink\r\n\t{color:#0563C1;\r\n\ttext-decoration:underline}\r\na:visited, 
  span.MsoHyperlinkFollowed\r\n\t{color:#954F72;\r\n\ttext-decoration:underline}\r\nspan.EmailStyle17\r\n\t{font-family:\"Calibri\",sans-serif;\r\n\tcolor:windowtext}\r\n.MsoChpDefault\r\n\t{font-family:\"Calibri\",sans-serif}\r\n@page 
  WordSection1\r\n\t{margin:72.0pt 72.0pt 72.0pt 72.0pt}\r\ndiv.WordSection1\r\n\t{}\r\n-->\r\n</style>\r\n</head>\r\n<body 
  lang=\"EN-US\" link=\"#0563C1\" vlink=\"#954F72\">\r\n<div class=\"WordSection1\">\r\n<p 
  class=\"MsoNormal\"><span lang=\"HE\" dir=\"RTL\" style=\"font-size:11.0pt; 
  font-family:&quot;Arial&quot;,sans-serif\">\u05d4\u05e0\u05d4 \u05e7\u05d5\u05d1\u05e5</span><span 
  style=\"font-size:11.0pt\"></span></p>\r\n</div>\r\n</body>\r\n</html>\r\n",
      "CCRecipients":null,
      "From":{  
         "Name":"Bar Hochman",
         "Address":"se@example.com"
      },
      "Sender":{  
         "Name":"Bar Hochman",
         "Address":"se@example.com"
      },
      "Created":"2019-04-24T06:42:01Z",
      "HasAttachments":true,
      "ReceivedTime":"2019-04-24T06:42:02Z",
      "UserID":"ex@example.com",
      "IsDraft":false,
      "ReplyTo":null,
      "BCCRecipients":null,
      "LastModifiedTime":"2019-04-24T06:48:35Z",
      "Subject":"\u05e7\u05d1\u05dc 
  \u05e7\u05d5\u05d1\u05e5 \u05e8\u05e0\u05d3\u05d5\u05de\u05d0\u05dc\u05d9",
      "ID":"AAMkADMzZWNjMjBkZoON8u7AAAF0Z9-AAA=",
      "Categories":[  

      ],
      "SendTime":"2019-04-24T06:41:56Z"
   }
}
```

##### Human Readable 
### Results for message ID AAMkADMzZCPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA=
ID|Subject|SendTime|Sender|From|HasAttachments|Body|
|---|---|---|---|---|---|---|
|AAMkADMzZWF0Z9-AAA=|Get a random file|2019-04-24T06:41:56Z|Name: Ba Hoch Address: se@example.com|Name: Ba Hoch Address: se@example.com|true|File goes here|


### 3. msgraph-mail-delete-email
---
Deletes an email.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-delete-email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (mostly email address). | Required | 
| message_id | Message ID. | Required | 
| folder_id | Folder ID (Comma sepreated, mailFolders,childFolders,childFolders...). | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!msgraph-mail-delete-email user_id=ex@example.com message_id=4jn43h2%$@nf=```


### 4. msgraph-mail-list-attachments
---
Lists all of the attachments of given email
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-list-attachments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (mostly email address). | Required | 
| message_id | Message ID. | Required | 
| folder_id | Folder ID (Comma sepreated, mailFolders,childFolders,childFolders...). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMailAttachment.ID | String | Email ID. | 
| MSGraphMailAttachment.Attachment.ID | String | ID of attachment. | 
| MSGraphMailAttachment.Attachment.Name | String | Name of attachment. | 
| MSGraphMailAttachment.Attachment.Type | String | Type of attachment. | 
| MSGraphMailAttachment.UserID | String | ID of user | 


##### Command Example
```!msgraph-mail-list-attachments user_id=ex@example.com message_id=AAMkADMzZWNjMjBkLTE2PVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA=```

####Context Example
```
{  
   "MSGraphMailAttachment":{  
      "UserID":"ex@example.com",
      "Attachment":[  
         {  
            "Type":"image/png",
            "ID":"AAMkADMzZWNjMjBkLTE2ZGQqF1VbAHI=",
            "Name":"download-1.png"
         }
      ],
      "ID":"AAMkADMzZWNjMjBkLTE2ZGQtNDN8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA="
   }
}
```

##### Human Readable Output
### Total of 1 attachments found in message AAMkADMzZWNjMjBkLTENF6ZoON8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA= from user ex@example.com
File names|
|---|
|download-1.png|

### 5. msgraph-mail-get-attachment
---
Gets an attachment from the email.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-get-attachment`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID (mostly email address). | Required | 
| message_id | Message ID. | Required | 
| folder_id | Folder ID (Comma sepreated, mailFolders,childFolders,childFolders...). | Optional | 
| attachment_id | ID of the attachment. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | Size of file | 
| File.SHA1 | String | File's SHA1 | 
| File.SHA256 | String | File's SHA256 | 
| File.Name | String | File's name | 
| File.SSDeep | String | File's SSDeep | 
| File.EntryID | String | File's entry id | 
| File.Info | String | File's info | 
| File.Type | String | File's type | 
| File.MD5 | String | File's MD5 | 
| File.Extension | String | File's Extension | 


##### Command Example
```!msgraph-mail-get-attachment user_id=ex@example.com message_id=AAMkADMzZWNjO3YRKNF6ZoON8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA= attachment_id=AAMkADCPVsAqlO3YRKNF6ZoON8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAABEgAQAFBdvAbOjGxNvBHqF1VbAHI=```

##### Human Readable Output


### 6. msgraph-mail-list-folders
---
Returns the mail folder list directly under the root folder.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-list-folders`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID. This is generally an email address in the format someuser@example.com. | Required | 
| limit | The maximum number of mail folder lists to return. | Optional | 


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
```!msgraph-mail-list-folders user_id=ex@example.com limit=5 ```

##### Context Example
```
{
    "MSGraphMail.Folders": [
        {
            "DisplayName": "Archive", 
            "ChildFolderCount": 0, 
            "UnreadItemCount": 0, 
            "ID": "folder_id_1", 
            "TotalItemCount": 1, 
            "ParentFolderID": "parent_folder_id_1"
        }, 
        {
            "DisplayName": "Conversation History", 
            "ChildFolderCount": 1, 
            "UnreadItemCount": 0, 
            "ID": "folder_id_2", 
            "TotalItemCount": 0, 
            "ParentFolderID": "parent_folder_id_2"
        }, 
        {
            "DisplayName": "Copy", 
            "ChildFolderCount": 0, 
            "UnreadItemCount": 0, 
            "ID": "folder_id_3", 
            "TotalItemCount": 0, 
            "ParentFolderID": "parent_folder_id_3"
        }, 
        {
            "DisplayName": "Deleted Items", 
            "ChildFolderCount": 1, 
            "UnreadItemCount": 81, 
            "ID": "folder_id_4", 
            "TotalItemCount": 90, 
            "ParentFolderID": "parent_folder_id_4"
        }, 
        {
            "DisplayName": "Test", 
            "ChildFolderCount": 0, 
            "UnreadItemCount": 0, 
            "ID": "folder_id_5", 
            "TotalItemCount": 5, 
            "ParentFolderID": "parent_folder_id_5"
        }
    ]
}
```

##### Human Readable Output
### Mail Folder collection under root folder for user ex@example.com
|ChildFolderCount|DisplayName|ID|ParentFolderID|TotalItemCount|UnreadItemCount|
|---|---|---|---|---|---|
| 0 | Archive | folder_id_1 | parent_folder_id_1 | 1 | 0 |
| 1 | Conversation History | folder_id_2 | parent_folder_id_2 | 0 | 0 |
| 0 | Copy | folder_id_3 | parent_folder_id_3 | 0 | 0 |
| 1 | Deleted Items | folder_id_4 | parent_folder_id_4 | 90 | 81 |
| 0 | Test | folder_id_5 | parent_folder_id_5 | 5 | 0 |


### 7. msgraph-mail-list-child-folders
---
Returns the folder list under the specified folder.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-list-child-folders`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID. This is generally an email address in the format someuser@example.com. | Required | 
| parent_folder_id | The ID of the parent folder. | Required | 
| limit | The maximum number of mail folder lists to return. | Optional | 


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
```!msgraph-mail-list-child-folders parent_folder_id=parent_folder_id user_id= ex@example.com```

##### Context Example
```
{
    "MSGraphMail.Folders": [
        {
            "DisplayName": "Test", 
            "ChildFolderCount": 0, 
            "UnreadItemCount": 1, 
            "ID": "folder_id", 
            "TotalItemCount": 1, 
            "ParentFolderID": "parent_folder_id"
        }
    ]
}
```

##### Human Readable Output
### Mail Folder collection under parent_folder_id folder for user ex@example.com
|ChildFolderCount|DisplayName|ID|ParentFolderID|TotalItemCount|UnreadItemCount|
|---|---|---|---|---|---|
| 0 | Phishing | folder_id | parent_folder_id | 1 | 1 |


### 8. msgraph-mail-create-folder
---
Creates a new folder under specified the specified folder (parent).
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-create-folder`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID. This is generally an email address in the format someuser@example.com. | Required | 
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
```!msgraph-mail-create-folder user_id=ex@example.com new_folder_name="New Folder" parent_folder_id=parent_folder_id```

##### Context Example
```
{
    "MSGraphMail.Folders": [
        {
            "DisplayName": "New Folder", 
            "ChildFolderCount": 0, 
            "UnreadItemCount": 0, 
            "ID": "new_folder_id", 
            "TotalItemCount": 0, 
            "ParentFolderID": "parent_folder_id"
        }
    ]
}
```

##### Human Readable Output
### Mail folder was created with display name: New Folder
|ChildFolderCount|DisplayName|ID|ParentFolderID|TotalItemCount|UnreadItemCount|
|---|---|---|---|---|---|
| 0 | New Folder | new_folder_id | parent_folder_id | 0 | 0 |


### 9. msgraph-mail-update-folder
---
Updates the properties of the specified folder.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-update-folder`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID. This is generally an email address in the format someuser@example.com. | Required | 
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
```!msgraph-mail-update-folder user_id="ex@example.com" folder_id=parent_folder_id new_display_name="Updated folder"```

##### Context Example
```
{
    "MSGraphMail": {
        "Folders": {
            "ChildFolderCount": 0,
            "DisplayName": "Updated folder",
            "ID": "updated_folder_id",
            "ParentFolderID": "parent_folder_id",
            "TotalItemCount": 0,
            "UnreadItemCount": 0
        }
    }
}
```

##### Human Readable Output
### Mail folder updated_folder_id was updated with display name: Updated folder
|ChildFolderCount|DisplayName|ID|ParentFolderID|TotalItemCount|UnreadItemCount|
|---|---|---|---|---|---|
| 0 | Updated folder | updated_folder_id | parent_folder_id | 0 | 0 |



### 10. msgraph-mail-delete-folder
---
Deletes the specified mail folder.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-delete-folder`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID. This is generally an email address in the format someuser@example.com. | Required | 
| folder_id | The ID of the folder to delete. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!msgraph-mail-delete-folder user_id="ex@example.com" folder_id="deleted_folder_id"```

##### Human Readable Output
The folder deleted_folder_id was deleted successfully


### 11. msgraph-mail-move-email
---
Moves a message to a different folder.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-move-email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Message ID. | Required | 
| destination_folder_id | The ID of the destination folder. | Required | 
| user_id | User ID or principal ID. This is generally an email address in the format someuser@example.com. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphMail.MovedEmails.DestinationFolderID | String | The folder to where the email message was moved. | 
| MSGraphMail.MovedEmails.ID | String | The new ID of the moved email message. | 
| MSGraphMail.MovedEmails.UserID | String | The user ID. | 


##### Command Example
```!msgraph-mail-move-email message_id=message_id destination_folder_id=destination_folder_id user_id="ex@example.com"```

##### Human Readable Output
### The email was moved successfully. Updated email data:
|DestinationFolderID|ID|UserID|
|---|---|---|
| destination_folder_id | new_item_id | ex@example.com |



### 12. msgraph-mail-get-email-as-eml
---
Retrieves an email message by message ID and uploads the content as an EML file.
##### Required Permissions
This command requires the following permissions.

* Mail.ReadWrite
* Directory.Read.All
* User.Read
##### Base Command

`msgraph-mail-get-email-as-eml`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID or principal ID. This is generally an email address in the format someuser@example.com. | Required | 
| message_id | Message ID. | Required | 


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
```!msgraph-mail-get-email-as-eml user_id="ex@example.com" message_id=message_id```

##### Human Readable Output


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
