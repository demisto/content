Enables interaction with the Zoom Mail API.

## Configure Zoom Mail in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://api.zoom.us/v2) |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| Maximum number of alerts per fetch |  | False |
| Client ID |  | True |
| Client Secret |  | True |
| Account ID |  | True |
| First fetch time |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incidents Fetch Interval |  | False |
| Fetch Mailbox | Mailbox to fetch incidents from | False |
| Fetch Query | Elastic query to filter messages in the specified inbox. | False |
| Fetch Labels | Specify the folder that the messages will be fetched from. | False |
| Include Threads when Fetching |  | False |


## Scopes Required
### Classic Scopes
- mail:read
- mail:write
- user:read
### Granular Scopes
- email:read:list_msgs
- email:write:trash_msg
- email:read:list_threads
- email:read:thread
- email:read:attachment
- email:write:send_msg
- email:read:profile
- user:read:list_users:admin

## Additional Resources
- [API credentials creation (server-to-server)](https://developers.zoom.us/docs/internal-apps/create/)
- [Internal apps (server-to-server)](https://developers.zoom.us/docs/internal-apps/)

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zoom-mail-email-move-trash

***
Move a message to the trash.

#### Base Command

`zoom-mail-email-move-trash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The target mailbox to delete the email from. | Optional | 
| message_id | The message_id of the message to delete. | Required | 

#### Context Output

There is no context output for this command.
### zoom-mail-email-list

***
Lists the messages in the user's mailbox.

#### Base Command

`zoom-mail-email-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The target mailbox to list emails. | Optional | 
| query | Query to filter emails within the given mailbox. | Optional | 
| max_results | Maximum number of emails to list. | Optional | 
| page_token | The token for the next page of results. | Optional | 
| include_spam_trash | Whether or not to include spam or trash messages in the results. | Optional | 
| message_id | The immutable message ID. | Optional | 
| format | The format to return the message with. Possible values are: full, metadata, minimal. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZoomMail.Email.messages.id | string | The ID of the email message. | 
| ZoomMail.Email.messages.threadId | string | The ID of the email thread. | 
| ZoomMail.Email.resultSizeEstimate | number | The estimated amount of messages found. | 
| ZoomMail.Email.messages.labelIds | string | The labels assigned to the email. | 
| ZoomMail.Email.messages.snippet | string | A snippet of the email content. | 
| ZoomMail.Email.messages.historyId | string | The history ID of the email. | 
| ZoomMail.Email.messages.internalDate | date | The internal date of the email. | 
| ZoomMail.Email.messages.expiration | number | The expiration time of the email. | 
| ZoomMail.Email.messages.lastMoved | date | The last moved timestamp of the email. | 
| ZoomMail.Email.messages.sendTime | date | The send time of the email. | 
| ZoomMail.Email.messages.userScheduled | boolean | Indicates if the email was user scheduled. | 
| ZoomMail.Email.messages.manifest | string | The manifest of the email. | 
| ZoomMail.Email.messages.originalMime | string | The original MIME of the email. | 
| ZoomMail.Email.messages.payload.partId | string | The part ID of the email payload. | 
| ZoomMail.Email.messages.payload.mimeType | string | The MIME type of the email payload. | 
| ZoomMail.Email.messages.payload.filename | string | The filename of the email payload. | 
| ZoomMail.Email.messages.payload.headers | unknown | The headers of the email payload. | 
| ZoomMail.Email.messages.payload.body.attachmentId | string | The attachment ID of the email body. | 
| ZoomMail.Email.messages.payload.body.size | number | The size of the email body. | 
| ZoomMail.Email.messages.payload.body.data | string | The data of the email body. | 
| ZoomMail.Email.messages.payload.parts | unknown | The parts of the email payload. | 
| ZoomMail.Email.sizeEstimate | number | The size estimate of the email. | 
| ZoomMail.Email.raw | string | The raw content of the email. |  

### zoom-mail-thread-list

***
Get an email thread.

#### Base Command

`zoom-mail-thread-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The target mailbox to list emails. | Optional | 
| thread_id | Unique identifier for the email thread you want to retrieve. | Optional | 
| format | Specifies the format in which the email messages in the thread should be returned. Possible values are: full, metadata, minimal. | Optional | 
| metadata_headers | When the format is set to metadata, this argument allows you to specify which email headers should be included in the response. | Optional | 
| max_results | Default is 50. | Optional | 
| page_token | The token for the next page of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZoomMail.Thread.id | string | The ID of the email thread. | 
| ZoomMail.Thread.status | string | The status of the email thread. | 
| ZoomMail.Thread.threadName | string | The name of the email thread. | 
| ZoomMail.Thread.messages | unknown | The messages found in the email thread. | 

### zoom-mail-email-attachment-get

***
Get an email attachment.

#### Base Command

`zoom-mail-email-attachment-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address of the inbox. | Optional | 
| message_id | The immutable message ID. | Required | 
| attachment_id | The immutable attachment ID. | Required | 

#### Context Output

There is no context output for this command.
### zoom-mail-send-email

***
Sends an email message with support for plain text, HTML, and attachments.

#### Base Command

`zoom-mail-send-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | The sender address. | Optional | 
| to | The recipient address. | Required | 
| subject | The subject of the email. | Required | 
| body | The plain text body of the email. | Optional | 
| html_body | The HTML body of the email. | Optional | 
| attachments | Comma-separated list of War Room entry IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZoomMail.Email.id | string | The id of the sent email. | 
| ZoomMail.Email.threadId | string | The id for the thread of the sent email. | 

### zoom-mail-mailbox-profile-get

***
Retrieves the mailbox profile.

#### Base Command

`zoom-mail-mailbox-profile-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The target mailbox. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZoomMail.Profile.status | string | The status of the mailbox profile. | 
| ZoomMail.Profile.emailAddress | string | The email address assigned to the mailbox profile. | 
| ZoomMail.Profile.messagesTotal | number | The total number of messages. | 
| ZoomMail.Profile.threadsTotal | number | The total number of threads. | 

### zoom-mail-user-list

***
Lists the available users.

#### Base Command

`zoom-mail-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the User. | Optional | 
| limit | The max amount of users to return per page. | Optional | 
| role_id | The ID for the role of the User. | Optional | 
| page_number | The page number of results. | Optional | 
| include_fields | Indicates whether or not to include fields. | Optional | 
| next_token | The token used to fetch the next page. | Optional | 
| license | Indicates if the user is licensed or not. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZoomMail.User.role_id | string | The ID of the users role. | 
| ZoomMail.User.display_name | string | The display name of the user. | 
| ZoomMail.User.id | string | The ID of the user. | 
| ZoomMail.User.email | unknown | The email for the user. | 