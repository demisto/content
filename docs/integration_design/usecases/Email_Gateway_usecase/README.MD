# Email Gateway
Top Use-Cases:
- [Get message – Download the email itself, retrieve metadata, body.](#get-message)
- [Download attachments for a given message.](#attachment-example)
- Manage senders – Block/ Allow specified mail senders.
- Manage URLs – Block/ Allow the sending of specified URLs.
- Encode/ Decode URLs in messages.
- Release a held message (The gateway can place suspicious messages on hold, and sometimes they would need to be released to the receiver).

**Email Gateway Integration Example** – Mimecast

## Command Examples

### msgraph-mail-get-email <a name="get-message"></a>
---
Gets the properties of an email.
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
`msgraph-mail-get-email message_id=AAMkADMzZWNjMgBGAAAAZoON8u7AAAF0Z9-AAA= user_id=ex@example.com get_body=true`

##### Context Example
```
{
    "MSGraphMail": {
        "Body": "<html>\r\n<head>\r\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\r\n<meta content=\"text/html; charset=utf-8\">\r\n<meta name=\"Generator\" content=\"Microsoft Word 15 (filtered medium)\">\r\n<style>\r\n<!--\r\n@font-face\r\n\t{font-family:\"Cambria Math\"}\r\n@font-face\r\n\t{font-family:Calibri}\r\np.MsoNormal, li.MsoNormal, div.MsoNormal\r\n\t{margin:0cm;\r\n\tmargin-bottom:.0001pt;\r\n\tfont-size:12.0pt;\r\n\tfont-family:\"Calibri\",sans-serif}\r\na:link, span.MsoHyperlink\r\n\t{color:#0563C1;\r\n\ttext-decoration:underline}\r\na:visited, span.MsoHyperlinkFollowed\r\n\t{color:#954F72;\r\n\ttext-decoration:underline}\r\nspan.EmailStyle17\r\n\t{font-family:\"Calibri\",sans-serif;\r\n\tcolor:windowtext}\r\n.MsoChpDefault\r\n\t{font-family:\"Calibri\",sans-serif}\r\n@page WordSection1\r\n\t{margin:72.0pt 72.0pt 72.0pt 72.0pt}\r\ndiv.WordSection1\r\n\t{}\r\n-->\r\n</style>\r\n</head>\r\n<body lang=\"EN-US\" link=\"#0563C1\" vlink=\"#954F72\">\r\n<div class=\"WordSection1\">\r\n<p class=\"MsoNormal\"><span lang=\"HE\" dir=\"RTL\" style=\"font-size:11.0pt; font-family:&quot;Arial&quot;,sans-serif\">\u05d4\u05e0\u05d4 \u05e7\u05d5\u05d1\u05e5</span><span style=\"font-size:11.0pt\"></span></p>\r\n</div>\r\n</body>\r\n</html>\r\n", 
        "CCRecipients": null, 
        "From": {
            "Name": "Bar Hochman", 
            "Address": "se@example.com"
        }, 
        "Sender": {
            "Name": "Bar Hochman", 
            "Address": "se@example.com"
        }, 
        "Created": "2019-04-24T06:42:01Z", 
        "HasAttachments": true, 
        "ReceivedTime": "2019-04-24T06:42:02Z", 
        "UserID": "ex@example.com", 
        "IsDraft": false, 
        "ReplyTo": null, 
        "BCCRecipients": null, 
        "LastModifiedTime": "2019-04-24T06:48:35Z", 
        "Subject": "\u05e7\u05d1\u05dc \u05e7\u05d5\u05d1\u05e5 \u05e8\u05e0\u05d3\u05d5\u05de\u05d0\u05dc\u05d9", 
        "ID": "AAMkADMzZWNjMjBkZoON8u7AAAF0Z9-AAA=", 
        "Categories": [], 
        "SendTime": "2019-04-24T06:41:56Z"
    }
}
```

##### Human Readable Output
### Results for message ID AAMkADMzZCPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA=
|ID|Subject|SendTime|Sender|From|HasAttachments|Body|
|---|---|---|---|---|---|---|
|AAMkADMzZWF0Z9-AAA=|קבל קובץ רנדומאלי|2019-04-24T06:41:56Z|Name: Bar Hochman<br>Address: se@example.com|Name: Bar Hochman<br>Address: se@example.com|true|<html><br><head><br><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><br><meta content="text/html; charset=utf-8"><br><meta name="Generator" content="Microsoft Word 15 (filtered medium)"><br><style><br><!--<br>@font-face<br>	{font-family:"Cambria Math"}<br>@font-face<br>	{font-family:Calibri}<br>p.MsoNormal, li.MsoNormal, div.MsoNormal<br>	{margin:0cm;<br>	margin-bottom:.0001pt;<br>	font-size:12.0pt;<br>	font-family:"Calibri",sans-serif}<br>a:link, span.MsoHyperlink<br>	{color:#0563C1;<br>	text-decoration:underline}<br>a:visited, span.MsoHyperlinkFollowed<br>	{color:#954F72;<br>	text-decoration:underline}<br>span.EmailStyle17<br>	{font-family:"Calibri",sans-serif;<br>	color:windowtext}<br>.MsoChpDefault<br>	{font-family:"Calibri",sans-serif}<br>@page WordSection1<br>	{margin:72.0pt 72.0pt 72.0pt 72.0pt}<br>div.WordSection1<br>	{}<br>--><br></style><br></head><br><body lang="EN-US" link="#0563C1" vlink="#954F72"><br><div class="WordSection1"><br><p class="MsoNormal"><span lang="HE" dir="RTL" style="font-size:11.0pt; font-family:&quot;Arial&quot;,sans-serif">הנה קובץ</span><span style="font-size:11.0pt"></span></p><br></div><br></body><br></html><br>|


### msgraph-mail-get-attachment <a name="attachment-example"></a>
---
Gets an attachment from the email.
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
`msgraph-mail-get-attachment user_id=ex@example.com message_id=!msgraph-mail-get-attachment user_id=ex@example.com message_id=AAMkADMzZWNjO3YRKNF6ZoON8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA= attachment_id=AAMkADCPVsAqlO3YRKNF6ZoON8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAABEgAQAFBdvAbOjGxNvBHqF1VbAHI=`

##### Context Example
```

```

##### Human Readable Output
