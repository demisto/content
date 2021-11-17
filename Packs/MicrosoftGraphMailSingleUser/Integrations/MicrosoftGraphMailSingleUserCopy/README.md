Microsoft Graph grants Demisto authorized access to a user's Microsoft Outlook mail data in a personal account or organization account.
This integration was integrated and tested with version xx of Microsoft Graph Mail Single User_copy

## Configure Microsoft Graph Mail Single User_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Graph Mail Single User_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | ID or Client ID - see Detailed Instructions (?) | True |
    | Token or Tenant ID - see Detailed Instructions (?) | True |
    | Key or Client Secret - see Detailed Instructions (?) | True |
    | Authorization code (required for self-deployed Azure app) | False |
    | Application redirect URI (required for self-deployed Azure app) | False |
    | Fetch incidents | False |
    | Email address from which to fetch incidents (e.g. "example@demisto.com") | True |
    | Name of the folder from which to fetch incidents (supports Folder ID and sub-folders e.g. Inbox/Phishing) | True |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
    | Maximum number of emails to pull per fetch | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Use a self-deployed Azure application | False |
    | Incident type | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| flag | The flag value that indicates the status of the draft. Can be: "notFlagged", "complete", or "flagged". Possible values are: notFlagged, complete, flagged. Default is notFlagged. | Optional | 
| importance | The importance of the draft. Can be: "Low", "Normal", or "High". Possible values are: Low, Normal, High. Default is Low. | Optional | 
| headers | A comma-separated list of additional headers in the format, headerName:headerValue. For example, "headerName1:headerValue1,headerName2:headerValue2". | Optional | 
| attach_ids | A comma-separated list of War Room entry IDs that contain files, which are used to attach files to the draft. For example, attachIDs=15@8,19@8. | Optional | 
| attach_names | A comma-separated list of names of attachments to be displayed in the draft. Must be the same number of elements as attachIDs. | Optional | 
| attach_cids | A comma-separated list of CIDs to embed attachments within the actual email. | Optional | 


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


#### Command Example
``` ```

#### Human Readable Output



### reply-mail
***
Replies to an email using Graph Mail Single User.


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


#### Command Example
``` ```

#### Human Readable Output



### send-mail
***
Sends an email using Microsoft Graph.


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
| flag | The flag value that indicates the status for the email. Can be: "notFlagged", "complete", or "flagged". Possible values are: notFlagged, complete, flagged. Default is notFlagged. | Optional | 
| importance | The importance of the email. Can be: "Low", "Normal", or "High". Possible values are: Low, Normal, High. Default is Low. | Optional | 
| headers | A comma-separated list of additional headers in the format: headerName:headerValue. For example: "headerName1:headerValue1,headerName2:headerValue2". | Optional | 
| attach_ids | A comma-separated list of War Room entry IDs that contain files, which are used to attach files for the email to send. For example, attachIDs=15@8,19@8. | Optional | 
| attach_names | A comma-separated list of names of attachments to display in the email to send. Must be the same number of elements as attachIDs. | Optional | 
| attach_cids | A comma-separated list of CIDs to embed attachments within the actual email. | Optional | 


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


#### Command Example
``` ```

#### Human Readable Output



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


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### msgraph-mail-send-draft
***
Sends a draft email using Microsoft Graph.


#### Base Command

`msgraph-mail-send-draft`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| draft_id | The ID of the draft email. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



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

#### Command Example
``` ```

#### Human Readable Output


