Enables interaction with the Zoom Mail API.

## Configure Zoom Mail on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Zoom Mail.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://api.zoom.us/v2) |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Maximum number of alerts per fetch |  | False |
    | Client ID |  | True |
    | Client Secret |  | True |
    | First fetch time |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |
    | Account ID |  | False |
    | Fetch Mailbox | Mailbox to fetch incidents from | False |
    | Fetch Query | Elastic query to filter messages in the specified inbox. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zoom-mail-trash-email

***
Move a message to the trash.

#### Base Command

`zoom-mail-trash-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The target mailbox to delete the email from. | Required | 
| message_id | The message_id of the message to delete. | Required | 

#### Context Output

There is no context output for this command.
### zoom-mail-list-emails

***
Lists the messages in the user's mailbox.

#### Base Command

`zoom-mail-list-emails`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The target mailbox to list emails. | Required | 
| query | Query to filter emails within the given mailbox. | Optional | 
| max_results | Maximum number of emails to list. | Optional | 
| page_token | The token for the next page of results. | Optional | 
| include_spam_trash | Whether or not to include spam or trash messages in the results. | Optional | 

#### Context Output

There is no context output for this command.
### zoom-mail-get-email-thread

***
Get an email thread.

#### Base Command

`zoom-mail-get-email-thread`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The target mailbox to list emails. | Required | 
| thread_id | Unique identifier for the email thread you want to retrieve. | Optional | 
| format | Specifies the format in which the email messages in the thread should be returned. Possible values are: full, metadata, minimal. | Optional | 
| metadata_headers | When the format is set to metadata, this argument allows you to specify which email headers should be included in the response. | Optional | 
| max_results | Default is 50. | Optional | 
| page_token | The token for the next page of results. | Optional | 

#### Context Output

There is no context output for this command.
### zoom-mail-get-email-attachment

***
Get an email attachment.

#### Base Command

`zoom-mail-get-email-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address of the inbox. | Required | 
| message_id | The immutable message ID. | Required | 
| attachment_id | The immutable attachment ID. | Required | 

#### Context Output

There is no context output for this command.
### zoom-mail-get-email-message

***
Retrieves the specified email message.

#### Base Command

`zoom-mail-get-email-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The target mailbox. | Required | 
| message_id | The immutable message ID. | Required | 
| format | The format to return the message with. Possible values are: full, metadata, minimal. | Optional | 

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
| from | The sender address. | Required | 
| to | The recipient address. | Required | 
| subject | The subject of the email. | Optional | 
| body | The plain text body of the email. | Optional | 
| html_body | The HTML body of the email. | Optional | 
| attachments | Comma-separated list of War Room entry IDs. | Optional | 

#### Context Output

There is no context output for this command.
### zoom-mail-get-mailbox-profile

***
Retrieves the mailbox profile.

#### Base Command

`zoom-mail-get-mailbox-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The target mailbox. | Optional | 

#### Context Output

There is no context output for this command.
### zoom-mail-list-users

***
Lists the available users.

#### Base Command

`zoom-mail-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the User. | Optional | 
| page_size | The max amount of users to return per page. | Optional | 
| role_id | The ID for the role of the User. | Optional | 
| page_number | The page number of results. | Optional | 
| include_fields | Indicates whether or not to include fields. | Optional | 
| next_page_token | The token used to fetch the next page. | Optional | 
| license | Indicates if the user is licensed or not. | Optional | 

#### Context Output

There is no context output for this command.
