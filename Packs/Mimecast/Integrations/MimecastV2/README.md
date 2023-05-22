Mimecast unified email management offers cloud email services for email security, continuity and archiving emails.
Please read detailed instructions in order to understand how to set the integration's parameters.

## Configure Mimecast v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Mimecast v2.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Required** |
   | --- | --- |
   | BaseUrl - API url including region, For example https://eu-api.mimecast.com | True |
   | App ID | True |
   | User Email Address (Use for auto token refresh) | False |
   | Password | False |
   | App key | False |
   | AccessKey | False |
   | SecretKey | False |
   | Trust any certificate (not secure) | False |
   | Use system proxy settings | False |
   | Fetch incidents | False |
   | Fetch URL incidents | False |
   | Fetch attachment incidents | False |
   | Fetch impersonation incidents | False |
   | Incident type | False |
   | Hours before first fetch to retrieve incidents | False |
   | Incident type | False |
   | Fetch incidents | False |
   | Incident type | False |
   | Fetch incidents | False |
   | Incident type | False |
   | Fetch incidents | False |

> **Note:** The fields `User Email Address (Use for auto token refresh)` and `Password` are not mandatory fields. You will only need them if you have expiry set on the auth of the user account you use to create the API keys. They will be used to auto refresh the API key once it expires.

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

### mimecast-query

***
Query Mimecast emails. This is an archive search command.

#### Base Command

`mimecast-query`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| queryXml          | The query string xml for the search using Mimecast Unified Search Experience (MUSE) - read more on https://community.mimecast.com/docs/DOC-2262, using this will override other query arguments.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Optional     | 
| text              | Search for this text in messages.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Optional     | 
| dryRun            | Will not execute the query, but just return the query string built. Possible values are: true, false. Default is false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Optional     | 
| date              | Search in specific dates only. Possible values are: today, yesterday, last_week, last_month, last_year.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Optional     | 
| dateFrom          | Search emails from date, format YYYY-MM-DDTHH:MM:SZ (e.g. 2015-09-21T23:00:00Z).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Optional     | 
| dateTo            | Search emails to date, format YYYY-MM-DDTHH:MM:SZ (e.g. 2015-09-21T23:00:00Z).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional     | 
| sentTo            | Filter on messages to a specific address.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional     | 
| sentFrom          | Filter on messages from a specific address.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Optional     | 
| subject           | Search email by subject, will override the text argument.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional     | 
| attachmentType    | These are the attachment types available: optional - messages with and without attachments any - messages with any attachment documents - messages with doc, dot, docx, docm, dotx, dotm, pdf, rtf, html attachments spreadsheets - messages with xls, xlt, xlsx, xlsm, xltx, xltm, xlsb, xlam, csv attachments presentations - messages with ppt, pptx, pptm, potx, potm, ppam, ppsx, ppsm, sldx, sldm, thms, pps attachments text - messages with txt, text, html, log attachments images - messages with jpg, jpeg, png, bmp, gif, psd, tif, tiff attachments media - messages with mp3, mp4, m4a, mpg, mpeg, avi, wav, aac, wma, mov attachments zips - messages with zip, rar, cab, gz, gzip, 7z attachments none - No attachments are to be present in the results. Possible values are: optional, any, documents, spreadsheets, presentations, text, images, media, zips, none. | Optional     | 
| attachmentText    | Search for text in attachments.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Optional     | 
| body              | Search email by text in body, will override the text and subject arguments.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Optional     | 
| page_size         | Number of results per page to display. Possible values are: .                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Optional     | 
| startRow          | This parameter is ignored, use the pagination parameters instead. Possible values are: .                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Optional     | 
| active            | Defines if the search should query recently received messages that are not fully processed yet (default false). You can search by mailbox and date time across active messages. Possible values are: true, false. Default is false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Optional     | 
| limit             | The maximum number of results to return. Possible values are: . Default is 100.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Optional     | 
| page              | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. Possible values are: .                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Optional     | 

#### Context Output

| **Path**                         | **Type** | **Description**                  |
|----------------------------------|----------|----------------------------------|
| Mimecast.Message.ID              | string   | Message ID                       | 
| Mimecast.Message.Subject         | string   | Message subject                  | 
| Mimecast.Message.Sender          | string   | Message sender address           | 
| Mimecast.Message.Recipient       | string   | Message recipient address        | 
| Mimecast.Message.RecievedDate    | date     | Message received date            | 
| Mimecast.Message.Size            | number   | The size of the message in bytes | 
| Mimecast.Message.AttachmentCount | number   | Message attachments count        | 
| Mimecast.Message.Status          | string   | Message status                   | 

### mimecast-list-blocked-sender-policies

***
List all existing Mimecast blocked sender policies

#### Base Command

`mimecast-list-blocked-sender-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|

#### Context Output

| **Path**                         | **Type** | **Description**                        |
|----------------------------------|----------|----------------------------------------|
| Mimecast.Policy.ID               | string   | Policy ID                              | 
| Mimecast.Policy.Sender.Address   | string   | Block Sender by email address          | 
| Mimecast.Policy.Sender.Domain    | string   | Block Sender by domain                 | 
| Mimecast.Policy.Sender.Group     | string   | Block Sender by group                  | 
| Mimecast.Policy.Bidirectional    | boolean  | Blocked policy is bidirectional or not | 
| Mimecast.Policy.Receiver.Address | string   | Block emails to receiver type address  | 
| Mimecast.Policy.Receiver.Domain  | string   | Block emails to receiver type domain   | 
| Mimecast.Policy.Receiver.Group   | string   | Block emails to receiver type group    | 
| Mimecast.Policy.FromDate         | date     | Policy validation start date           | 
| Mimecast.Policy.ToDate           | date     | Policy expiration date                 | 
| Mimecast.Policy.Sender.Type      | string   | Block emails to sender type            | 
| Mimecast.Policy.Receiver.Type    | string   | Block emails to receiver type          | 

### mimecast-get-policy

***
Get a blocked sender policy by ID

#### Base Command

`mimecast-get-policy`

#### Input

| **Argument Name** | **Description**      | **Required** |
|-------------------|----------------------|--------------|
| policyID          | Filter by policy ID. | Required     | 

#### Context Output

| **Path**                         | **Type** | **Description**                        |
|----------------------------------|----------|----------------------------------------|
| Mimecast.Policy.ID               | string   | Policy ID                              | 
| Mimecast.Policy.Sender.Address   | string   | Block Sender by email address          | 
| Mimecast.Policy.Sender.Domain    | string   | Block Sender by domain                 | 
| Mimecast.Policy.Sender.Group     | string   | Block Sender by group                  | 
| Mimecast.Policy.Bidirectional    | boolean  | Blocked policy is bidirectional or not | 
| Mimecast.Policy.Receiver.Address | string   | Block emails to receiver type address  | 
| Mimecast.Policy.Receiver.Domain  | string   | Block emails to receiver type domain   | 
| Mimecast.Policy.Receiver.Group   | string   | Block emails to receiver type group    | 
| Mimecast.Policy.Fromdate         | date     | Policy validation start date           | 
| Mimecast.Policy.Todate           | date     | Policy expiration date                 | 

### mimecast-create-policy

***
Create a Blocked Sender Policy

#### Base Command

`mimecast-create-policy`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                               | **Required** |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| description       | Policy description.                                                                                                                                                                                                                                                                           | Required     | 
| fromPart          | Addresses based on. Possible values are: envelope_from, header_from, both. Default is envelope_from.                                                                                                                                                                                          | Optional     | 
| fromType          | Blocked Sender type. Possible values are: everyone, internal_addresses, external_addresses, email_domain, profile_group, individual_email_address.                                                                                                                                            | Required     | 
| fromValue         | Required if fromType is one of email domain, profile group, individual email address. Expected values: If fromType is email_domain, a domain name without the @ symbol. If fromType is profile_group, the ID of the profile group. If fromType is individual_email_address, an email address. | Optional     | 
| toType            | Receiver type. Possible values are: everyone, internal_addresses, external_addresses, email_domain, profile_group, address_attribute_value, individual_email_address, free_mail_domains, header_display_name.                                                                                 | Required     | 
| toValue           | Required if fromType is one of email domain, profile group, individual email address. Expected values: If toType is email_domain, a domain name without the @ symbol. If toType is profile_group, the ID of the profile group. If toType is individual_email_address, an email address.       | Optional     | 
| option            | The block option, must be one of: no_action, block_sender. Possible values are: no_action, block_sender.                                                                                                                                                                                      | Required     | 

#### Context Output

| **Path**                         | **Type** | **Description**                        |
|----------------------------------|----------|----------------------------------------|
| Mimecast.Policy.ID               | string   | Policy ID                              | 
| Mimecast.Policy.Sender.Address   | string   | Block Sender by email address          | 
| Mimecast.Policy.Sender.Domain    | string   | Block Sender by domain                 | 
| Mimecast.Policy.Sender.Group     | string   | Block Sender by group                  | 
| Mimecast.Policy.Bidirectional    | boolean  | Blocked policy is Bidirectional or not | 
| Mimecast.Policy.Receiver.Address | string   | Block emails to receiver type address  | 
| Mimecast.Policy.Receiver.Domain  | string   | Block emails to receiver type domain   | 
| Mimecast.Policy.Receiver.Group   | string   | Block emails to receiver type group    | 
| Mimecast.Policy.Fromdate         | date     | Policy validation start date           | 
| Mimecast.Policy.Todate           | date     | Policy expiration date                 | 
| Mimecast.Policy.Sender.Type      | String   | The sender type                        | 
| Mimecast.Policy.Receiver.Type    | String   | The receiver type                      | 

### mimecast-delete-policy

***
Delete a Blocked Sender Policy

#### Base Command

`mimecast-delete-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| policyID          | Policy ID.      | Required     | 

#### Context Output

| **Path**           | **Type** | **Description** |
|--------------------|----------|-----------------|
| Mimecast.Policy.ID | string   | Policy ID       | 

### mimecast-manage-sender

***
Permit or block a specific sender

#### Base Command

`mimecast-manage-sender`

#### Input

| **Argument Name** | **Description**                                                                                                                    | **Required** |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------|--------------|
| sender            | The email address of sender to permit or block.                                                                                    | Required     | 
| recipient         | The email address of recipient to permit or block.                                                                                 | Required     | 
| action            | Choose to either "permit" (to bypass spam checks) or "block" (to reject the email). Possible values are: permit, block.            | Required     | 
| limit             | The maximum number of results to return. Possible values are: . Default is 100.                                                    | Optional     | 
| page              | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. Possible values are: . | Optional     | 
| page_size         | Number of results per page to display. Possible values are: .                                                                      | Optional     | 

#### Context Output

| **Path**                   | **Type** | **Description**                                      |
|----------------------------|----------|------------------------------------------------------|
| Mimecast.Managed.Sender    | string   | The email address of the sender                      | 
| Mimecast.Managed.Recipient | string   | The email address of the recipient                   | 
| Mimecast.Managed.Action    | string   | Chosen action                                        | 
| Mimecast.Managed.ID        | string   | The Mimecast secure ID of the managed sender object. | 

### mimecast-list-managed-url

***
Get a list of all managed URLs

#### Base Command

`mimecast-list-managed-url`

#### Input

| **Argument Name** | **Description**                 | **Required** |
|-------------------|---------------------------------|--------------|
| url               | Filter results by specific URL. | Optional     | 

#### Context Output

| **Path**                     | **Type** | **Description**                                                                               |
|------------------------------|----------|-----------------------------------------------------------------------------------------------|
| Mimecast.URL.Domain          | string   | The managed domain                                                                            | 
| Mimecast.URL.Disablelogclick | boolean  | If logging of user clicks on the URL is disabled                                              | 
| Mimecast.URL.Action          | string   | Either block of permit                                                                        | 
| Mimecast.URL.Path            | string   | The path of the managed URL                                                                   | 
| Mimecast.URL.matchType       | string   | Either explicit - applies to the full URL or domain - applies to all URL values in the domain | 
| Mimecast.URL.ID              | string   | The Mimecast secure ID of the managed URL                                                     | 
| Mimecast.URL.disableRewrite  | boolean  | If rewriting of this URL in emails is disabled                                                | 

### mimecast-create-managed-url

***
Create a managed URL on Mimecast

#### Base Command

`mimecast-create-managed-url`

#### Input

| **Argument Name**    | **Description**                                                                                                                                                                                   | **Required** |
|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| url                  | The URL to block or permit. Do not include a fragment (#).                                                                                                                                        | Required     | 
| action               | Set to "block" to block list the URL, "permit" to add to allow list. Possible values are: block, permit.                                                                                          | Required     | 
| matchType            | Set to "explicit" to block or permit only instances of the full URL. Set to "domain" to block or permit any URL with the same domain. Possible values are: explicit, domain. Default is explicit. | Optional     | 
| disableRewrite       | Disable rewriting of this URL in emails. Applies only if action = "permit". Default false. Possible values are: true, false. Default is false.                                                    | Optional     | 
| comment              | Add a comment about the managed URL.                                                                                                                                                              | Optional     | 
| disableUserAwareness | Disable User Awareness challenges for this URL. Applies only if action = "permit". Default false. Possible values are: true, false. Default is false.                                             | Optional     | 
| disableLogClick      | Disable logging of user clicks on the URL. Default is false. Possible values are: true, false. Default is false.                                                                                  | Optional     | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mimecast.URL.Domain | string | The managed domain | 
| Mimecast.URL.Action | string | Either block of permit | 
| Mimecast.URL.disableLogClick | string | If logging of user clicks on the URL is disabled | 
| Mimecast.URL.matchType | string | Either explicit - applies to the full URL or domain - applies to all URL values in the domain | 
| Mimecast.URL.ID | string | The Mimecast secure ID of the managed URL | 
| Mimecast.URL.disableRewrite | boolean | If rewriting of this URL in emails is disabled | 

### mimecast-list-messages

***
Get a list of messages for a given user. This is an archive search command. Required Permissions The following permissions
are required for this command.

- Mimecast administrator with at least one of the following permissions: Archive/Search/Read.
- or Mimecast user with delegate permissions to address or user.

#### Base Command

`mimecast-list-messages`

#### Input

| **Argument Name** | **Description**                                  | **Required** |
|------------------|--------------------------------------------------|--------------|
| mailbox          | The email address to return the message list for | Optional     |
| startTime        | The start date of messages to return, in the following format, 2015-11-16T14:49:18+0000. Default is the last calendar month   |Optional|
| endTime          | The end date of messages to return, in the following format, 2015-11-16T14:49:18+0000. Default is the end of the current day      |Optional|
| view                |  The message list type, must be one of: inbox or sent, default is inbox                                                    |Optional|
| subject                     |     Filter by message subject                 | Optional|
| limit | The maximum number of results to return. Default is 100. | Optional | 
| page | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. | Optional | 
| page_size | Number of results per page to display. | Optional | 

#### Context Output

| **Path**                          | **Type** | **Description**                          |
|-----------------------------------|----------|------------------------------------------|
| Mimecast.Message.Subject          | string   | Message Subject                          | 
| Mimecast.Message.ID                  | string   | Message ID                               | 
| Mimecast.Message.Size                | number   | The size of the message in bytes         | 
| Mimecast.Message.RecievedDate        | date     | The date the message was received        | 
| Mimecast.Message.From                | string   | The mail Sender                          | 
| Mimecast.Message.AttachmentCount     | string   | The number of attachments on the message | 

### mimecast-get-attachment-logs

***
Returns Attachment Protect logs for a Mimecast customer account

#### Base Command

`mimecast-get-attachment-logs`

#### Input

| **Argument Name** | **Description**                                                                                                                             | **Required** |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| resultsNumber     | This parameter is ignored, use the 'limit' parameter instead. Possible values are: .                                                        | Optional     | 
| fromDate          | Start date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is the start of the current day.                     | Optional     | 
| toDate            | End date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is time of request.                                    | Optional     | 
| resultType        | Filters logs by scan result, default is malicious. Possible values are: safe, malicious, timeout, error, unsafe, all. Default is malicious. | Optional     | 
| limit             | The maximum number of results to return. Default is 100.                                                                                    | Optional     | 
| page              | Page number you would like to view. Each page contains page_size values. Must be used along with page_size.                                 | Optional     | 
| page_size         | Number of results per page to display.                                                                                                      | Optional     | 

#### Context Output

| **Path**                         | **Type** | **Description**                                                                                             |
|----------------------------------|----------|-------------------------------------------------------------------------------------------------------------|
| Mimecast.AttachmentLog.Result    | string   | The result of the attachment analysis: clean, malicious, unknown, or timeout                                | 
| Mimecast.AttachmentLog.Date      | date     | The time at which the attachment was released from the sandbox                                              | 
| Mimecast.AttachmentLog.Sender    | string   | The sender of the attachment                                                                                | 
| Mimecast.AttachmentLog.FileName  | string   | The file name of the original attachment                                                                    | 
| Mimecast.AttachmentLog.Action    | string   | The action triggered for the attachment                                                                     | 
| Mimecast.AttachmentLog.Recipient | string   | The address of the user that received the attachment                                                        | 
| Mimecast.AttachmentLog.FileType  | string   | The file type of the attachment                                                                             | 
| Mimecast.AttachmentLog.Route     | string   | The route of the original email containing the attachment, either: inbound, outbound, internal, or external | 

### mimecast-get-url-logs

***
Returns URL protect logs for a Mimecast customer account. Default value of scanResult as malicious

#### Base Command

`mimecast-get-url-logs`

#### Input

| **Argument Name** | **Description**                                                                                                         | **Required** |
|-------------------|-------------------------------------------------------------------------------------------------------------------------|--------------|
| resultsNumber     | The number of results to request. Default is all                                                                        | Optional     | 
| fromDate          | Start date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is the start of the current day. | Optional     | 
| toDate            | End date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is time of request.                | Optional     | 
| resultType        | Filters logs by scan result, default is all                                                                             | Optional     | 
| limit             | The maximum number of results to return. Default is 100.                                                                | Optional     | 
| page              | Page number you would like to view. Each page contains page_size values. Must be used along with page_size.             | Optional     | 
| page_size         | Number of results per page to display.                                                                                  | Optional     | 

#### Context Output

| **Path**                      | **Type** | **Description**                                                                                             |
|-------------------------------|----------|-------------------------------------------------------------------------------------------------------------|
| Mimecast.UrlLog.Category      | string   | The category of the URL clicked                                                                             | 
| Mimecast.UrlLog.UserAddress   | string   | The email address of the user who clicked the link                                                          | 
| Mimecast.UrlLog.URL           | string   | The url clicked                                                                                             | 
| Mimecast.UrlLog.Awareness     | string   | The action taken by the user if user awareness was applied                                                  | 
| Mimecast.UrlLog.AdminOverride | string   | The action defined by the administrator for the URL                                                         | 
| Mimecast.UrlLog.Date          | date     | The date that the URL was clicked                                                                           | 
| Mimecast.UrlLog.Result        | string   | The result of the URL scan                                                                                  | 
| Mimecast.UrlLog.Action        | string   | The action that was taken for the click                                                                     | 
| Mimecast.UrlLog.Route         | string   | The route of the original email containing the attachment, either: inbound, outbound, internal, or external | 
| Mimecast.UrlLog. userOverride | string   | The action requested by the user.                                                                           | 

### mimecast-get-impersonation-logs

***
Returns Impersonation Protect logs for a Mimecast customer account

#### Base Command

`mimecast-get-impersonation-logs`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                  | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| resultsNumber     | This parameter is ignored, use the 'limit' parameter instead. Possible values are: .                                                                                                                                                                                                                                             | Optional     | 
| taggedMalicious   | Filters for messages tagged malicious (true) or not tagged malicious (false). Omit for no tag filtering. Default is true. Possible values are: true, false. Default is true.                                                                                                                                                     | Optional     | 
| searchField       | The field to search,Defaults is all (meaning all of the preceding fields). Possible values are: senderAddress, recipientAddress, subject, policy, all.                                                                                                                                                                           | Optional     | 
| query             | Required if searchField exists. A character string to search for in the logs.                                                                                                                                                                                                                                                    | Optional     | 
| identifiers       | Filters logs by identifiers, can include any of newly_observed_domain, internal_user_name, repy_address_mismatch, and targeted_threat_dictionary. you can choose more then one identifier separated by comma. Possible values are: newly_observed_domain, internal_user_name, repy_address_mismatch, targeted_threat_dictionary. | Optional     | 
| fromDate          | Start date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is the start of the current day.                                                                                                                                                                                                          | Optional     | 
| toDate            | End date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is time of request.                                                                                                                                                                                                                         | Optional     | 
| actions           | Filters logs by action, you can choose more then one action separated by comma. Possible values are: delete, hold, bounce, smart_folder, disable_smart_folder, content_expire, meta_expire, stationery, gcc, secure_delivery, delivery_route, document_policy, disable_document_policy, attach_set_policy, remove_email.         | Optional     | 
| limit             | The maximum number of results to return. Default is 100.                                                                                                                                                                                                                                                                         | Optional     | 
| page              | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. Possible values are: .                                                                                                                                                                                               | Optional     | 
| page_size         | Number of results per page to display. Possible values are: .                                                                                                                                                                                                                                                                    | Optional     | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mimecast.Impersonation.ResultCount | number | The total number of IMPERSONATION log lines found for the request | 
| Mimecast.Impersonation.Hits | number | The number of identifiers that the message triggered | 
| Mimecast.Impersonation.Malicious | boolean | Whether the message was tagged as malicious | 
| Mimecast.Impersonation.SenderIP | string | The source IP address of the message | 
| Mimecast.Impersonation.SenderAddress | string | The email address of the sender of the message | 
| Mimecast.Impersonation.Subject | string | The subject of the email | 
| Mimecast.Impersonation.Identifiers | string | The properties of the message that triggered the action: similar_internal_domain, newly_observed_domain, internal_user_name, reply_address_mismatch, and/or targeted_threat_dictionary | 
| Mimecast.Impersonation.Date | date | The time at which the log was recorded | 
| Mimecast.Impersonation.Action | string |  The action triggered by the email | 
| Mimecast.Impersonation.Policy | string | The name of the policy definition that triggered the log | 
| Mimecast.Impersonation.ID | string | Impersonation Log ID | 
| Mimecast.Impersonation.RecipientAddress | string | The email address of the recipient of the email | 
| Mimecast.Impersonation.External | boolean | Whether the message was tagged as coming from an external address | 

### mimecast-url-decode

***
Decodes a given url from mimecast

#### Base Command

`mimecast-url-decode`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to decode. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The encoded url to parse | 
| URL.Mimecast.DecodedURL | string | Parsed url | 

### mimecast-discover

***
discover authentication types that are supported for your account and which base URL to use for the requesting user.

#### Base Command

`mimecast-discover`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mimecast.Authentication.AuthenticationTypes | string | List of authentication types available to the user | 
| Mimecast.Authentication.EmailAddress | string | Email address of the request sender | 
| Mimecast.Authentication.EmailToken | string | Email token of the request sender | 

### mimecast-refresh-token

***
Refresh access key validity

#### Base Command

`mimecast-refresh-token`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### mimecast-login

***
Login to generate Access Key and Secret Key

#### Base Command

`mimecast-login`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### mimecast-get-message

***
Get the contents or metadata of a given message. This is an archive search command.

### Required Permissions

The following permissions are required for this command.

- Mimecast administrator with at least one of the following permissions: Archive/Search Content View.
- or Mimecast user with delegate permissions to address or user.

#### Base Command

`mimecast-get-message`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                 | **Required** |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| messageID         | Message ID                                                                                                                                                                                                                                                                                                      | Required     | 
| context           | Defines which copy of the message part to return, must be one of: "delivered" the copy that has been processed by the Mimecast MTA with policies such as URL rewriting applied, OR "received" - the copy of the message that Mimecast originally received. (Only relevant for part argument = message or all)   | Required     | 
| type              | The message type to return. (Only relevant for part argument = message or all)                                                                                                                                                                                                                                  | Optional     | 
| part              | Define what message part to return - download message, get metadata or both.                                                                                                                                                                                                                                    | Optional     | 

#### Context Output

| **Path**                              | **Type** | **Description**                                                    |
|---------------------------------------|----------|--------------------------------------------------------------------|
| Mimecast.Message.ID                   | string   | Message ID                                                         | 
| Mimecast.Message.Subject              | string   | The message subject.                                               | 
| Mimecast.Message.HeaderDate           | date     | The date of the message as defined in the message headers.         | 
| Mimecast.Message.Size                 | number   | The message size.                                                  | 
| Mimecast.Message.From                 | string   | Sender of the message as defined in the message header.            | 
| Mimecast.Message.To.EmailAddress      | string   | Recipient of the message.                                          | 
| Mimecast.Message.ReplyTo              | string   | The value of the Reply-To header.                                  | 
| Mimecast.Message.CC.EmailAddress      | string   | Each CC recipient of the message.                                  | 
| Mimecast.Message.EnvelopeFrom         | string   | Sender of the message as defined in the message envelope.          | 
| Mimecast.Message.Headers.Name         | string   | Header's name.                                                     | 
| Mimecast.Message.Headers.Values       | string   | Header's value.                                                    | 
| Mimecast.Message.Attachments.FileName | string   | Message attachment's file name.                                    | 
| Mimecast.Message.Attachments.SHA256   | string   | Message attachment's SHA256.                                       | 
| Mimecast.Message.Attachments.ID       | string   | Message attachment's ID.                                           | 
| Mimecast.Message.Attachments.Size     | number   | Message attachment's file size.                                    | 
| Mimecast.Message.Processed            | date     | The date the message was processed by Mimecast in ISO 8601 format. | 
| Mimecast.Message.HasHtmlBody          | boolean  | If the message has an HTML body part.                              | 
| File.Size                             | number   | File size                                                          | 
| File.SHA1                             | string   | SHA1 hash of the file                                              | 
| File.SHA256                           | string   | SHA256 hash of the file                                            | 
| File.Name                             | string   | The sample name                                                    | 
| File.SSDeep                           | string   | SSDeep hash of the file                                            | 
| File.EntryID                          | string   | War-Room Entry ID of the file                                      | 
| File.Info                             | string   | Basic information of the file                                      | 
| File.Type                             | string   | File type e.g. "PE"                                                | 
| File.MD5                              | string   | MD5 hash of the file                                               | 

### mimecast-download-attachments

***
Download attachments from a specified message. This is an archive search command.

#### Required Permissions

The following permissions are required for this command.

- Mimecast administrator with at least one of the following permissions: Archive/Search Content View.
- or Mimecast user with delegate permissions to address or user.

#### Base Command

`mimecast-download-attachments`

#### Input

| **Argument Name** | **Description**                                                                                   | **Required** |
|-------------------|---------------------------------------------------------------------------------------------------|--------------|
| attachmentID      | The Mimecast ID of the message attachment to return. (Can be retrieved from mimecast-get-message) | Required     |

#### Context Output

| **Path**     | **Type** | **Description**               |
|--------------|----------|-------------------------------|
| File.Size    | number   | File Size                     | 
| File.SHA1    | string   | SHA1 hash of the file         | 
| File.SHA256  | string   | SHA256 hash of the file       | 
| File.Name    | string   | The sample name               | 
| File.SSDeep  | string   | SSDeep hash of the file       | 
| File.EntryID | string   | War-Room Entry ID of the file | 
| File.Info    | string   | Basic information of the file | 
| File.Type    | string   | File type e.g., "PE"          | 
| File.MD5     | string   | MD5 hash of the file          | 

### mimecast-find-groups

***
Returns the list of groups according to the specified query.

#### Base Command

`mimecast-find-groups`

#### Input

| **Argument Name** | **Description**                                                         | **Required** |
|-------------------|-------------------------------------------------------------------------|--------------|
| query_string      | The string to query.                                                    | Optional     | 
| query_source      | The group source by which to filter. Possible values are: cloud, ldap.  | Optional     | 
| limit             | The maximum number of results to return.                                | Optional     | 

#### Context Output

| **Path**                           | **Type** | **Description**                        |
|------------------------------------|----------|----------------------------------------|
| Mimecast.Group.Name                | String   | The name of the group.                 | 
| Mimecast.Group.Source              | String   | The source of the group.               | 
| Mimecast.Group.ID                  | String   | The Mimecast ID of the group.          | 
| Mimecast.Group.NumberOfUsers       | Number   | The number of members in the group.    | 
| Mimecast.Group.ParentID            | String   | The Mimecast ID of the group's parent. | 
| Mimecast.Group.NumberOfChildGroups | Number   | The number of child groups.            | 

### mimecast-get-group-members

***
Returns the members list for the specified group.

#### Base Command

`mimecast-get-group-members`

#### Input

| **Argument Name** | **Description**                          | **Required** |
|-------------------|------------------------------------------|--------------|
| group_id          | The Mimecast ID of the group to return.  | Required     | 
| limit             | The maximum number of results to return. | Optional     | 

#### Context Output

| **Path**                          | **Type** | **Description**                              |
|-----------------------------------|----------|----------------------------------------------|
| Mimecast.Group.Users.Name         | String   | The user's display name.                     | 
| Mimecast.Group.Users.EmailAddress | String   | The user's email address.                    | 
| Mimecast.Group.Users.Domain       | String   | The domain name of the user's email address. | 
| Mimecast.Group.Users.Type         | String   | The user type.                               | 
| Mimecast.Group.Users.InternalUser | Boolean  | Whether the user is internal.                | 
| Mimecast.Group.Users.IsRemoved    | Boolean  | Whether the user is part of the group.       | 

### mimecast-add-group-member

***
Adds a user to a group. The email_address and domain_address arguments are optional, but one of them must be supplied.

#### Base Command

`mimecast-add-group-member`

#### Input

| **Argument Name** | **Description**                                  | **Required** |
|-------------------|--------------------------------------------------|--------------|
| group_id          | The Mimecast ID of the group to add the user to. | Required     | 
| email_address     | The email address of the user to add to a group. | Optional     | 
| domain_address    | A domain to add to a group.                      | Optional     | 

#### Context Output

| **Path**                          | **Type** | **Description**                        |
|-----------------------------------|----------|----------------------------------------|
| Mimecast.Group.Users.EmailAddress | String   | The user's email address.              | 
| Mimecast.Group.Users.IsRemoved    | Boolean  | Whether the user is part of the group. | 

### mimecast-remove-group-member

***
Removes a user from a group. The email_address and domain_address arguments are optional, but one of them must be
supplied.

#### Base Command

`mimecast-remove-group-member`

#### Input

| **Argument Name** | **Description**                                             | **Required** |
|-------------------|-------------------------------------------------------------|--------------|
| group_id          | The Mimecast ID of the group from which to remove the user. | Required     | 
| email_address     | The email address of the user to remove from the group.     | Optional     | 
| domain_address    | A domain of the user to remove from a group.                | Optional     | 

#### Context Output

| **Path**                          | **Type** | **Description**                     |
|-----------------------------------|----------|-------------------------------------|
| Mimecast.Group.Users.EmailAddress | String   | The user's email address.           | 
| Mimecast.Group.Users.IsRemoved    | Boolean  | Whether the user part of the group. | 

### mimecast-create-group

***
Creates a new Mimecast group.

#### Base Command

`mimecast-create-group`

#### Input

| **Argument Name** | **Description**                                                        | **Required** |
|-------------------|------------------------------------------------------------------------|--------------|
| group_name        | The name of the new group.                                             | Required     | 
| parent_id         | The Mimecast ID of the new group's parent. Default will be root level. | Optional     | 

#### Context Output

| **Path**                           | **Type** | **Description**                        |
|------------------------------------|----------|----------------------------------------|
| Mimecast.Group.Name                | String   | The name of the group.                 | 
| Mimecast.Group.Source              | String   | The source of the group.               | 
| Mimecast.Group.ID                  | String   | The Mimecast ID of the group.          | 
| Mimecast.Group.NumberOfUsers       | Number   | The number of members in the group.    | 
| Mimecast.Group.ParentID            | String   | The Mimecast ID of the group's parent. | 
| Mimecast.Group.NumberOfChildGroups | Number   | The number of child groups.            | 

### mimecast-update-group

***
Updates an existing Mimecast group.

#### Base Command

`mimecast-update-group`

#### Input

| **Argument Name** | **Description**                         | **Required** |
|-------------------|-----------------------------------------|--------------|
| group_name        | The new name for the group.             | Optional     | 
| group_id          | The Mimecast ID of the group to update. | Required     | 
| parent_id         | The new parent group.                   | Optional     | 

#### Context Output

| **Path**                | **Type** | **Description**                        |
|-------------------------|----------|----------------------------------------|
| Mimecast.Group.Name     | String   | The name of the group.                 | 
| Mimecast.Group.ID       | String   | The Mimecast ID of the group.          | 
| Mimecast.Group.ParentID | String   | The Mimecast ID of the group's parent. | 

### mimecast-create-remediation-incident

***
Creates a new Mimecast remediation incident.

#### Base Command

`mimecast-create-remediation-incident`

#### Input

| **Argument Name** | **Description**                                                                                                         | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------| --- |
| hash_message_id | The file hash or messageId value.                                                                                       | Required | 
| reason | The reason for creating the remediation incident.                                                                       | Required | 
| search_by | The message component by which to search. Default is "hash". Possible values are: hash, messageId.                      | Optional | 
| start_date | The start date of messages to remediate. Default value is the previous month. (Format: yyyy-mm-ddThh:mm:ss+0000).       | Optional | 
| end_date | The end date of messages to remediate. Default value is the end of the current day. (Format: yyyy-mm-ddThh:mm:ss+0000). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mimecast.Incident.ID | String | The secure Mimecast remediation ID. | 
| Mimecast.Incident.Code | String | The incident code generated at creation. | 
| Mimecast.Incident.Type | String | The incident type. | 
| Mimecast.Incident.Reason | String | The reason provided at the creation of the remediation incident. | 
| Mimecast.Incident.IdentifiedMessages | Number | The number of messages identified based on the search criteria. | 
| Mimecast.Incident.SuccessfullyRemediatedMessages | Number | The number successfully remediated messages. | 
| Mimecast.Incident.FailedRemediatedMessages | Number | The number of messages that failed to remediate. | 
| Mimecast.Incident.MessagesRestored | Number | The number of messages that were restored from the incident. | 
| Mimecast.Incident.LastModified | String | The date and time that the incident was last modified. | 
| Mimecast.Incident.SearchCriteria.From | String | The sender email address or domain. | 
| Mimecast.Incident.SearchCriteria.To | String | The recipient email address or domain. | 
| Mimecast.Incident.SearchCriteria.MessageID | String | The message ID used when creating the remediation incident. | 
| Mimecast.Incident.SearchCriteria.FileHash | String | The file hash used when creating the remediation incident. | 
| Mimecast.Incident.SearchCriteria.StartDate | String | The start date of included messages. | 
| Mimecast.Incident.SearchCriteria.EndDate | String | The end date of included messages. | 

### mimecast-get-remediation-incident

***
Returns a Mimecast remediation incident.

#### Base Command

`mimecast-get-remediation-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Mimecast ID for a remediation incident. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mimecast.Incident.ID | String | The secure Mimecast remediation ID. | 
| Mimecast.Incident.Code | String | The incident code generated at creation. | 
| Mimecast.Incident.Type | String | The incident type. | 
| Mimecast.Incident.Reason | String | The reason provided when the remediation incident was created. | 
| Mimecast.Incident.IdentifiedMessages | Number | The number of messages identified based on the search criteria. | 
| Mimecast.Incident.SuccessfullyRemediatedMessages | Number | The number of successfully remediated messages. | 
| Mimecast.Incident.FailedRemediatedMessages | Number | The number of messages that failed to remediate. | 
| Mimecast.Incident.MessagesRestored | Number | The number of messages that were restored from the incident. | 
| Mimecast.Incident.LastModified | String | The date and time that the incident was last modified. | 
| Mimecast.Incident.SearchCriteria.From | String | The sender email address or domain. | 
| Mimecast.Incident.SearchCriteria.To | String | The recipient email address or domain. | 
| Mimecast.Incident.SearchCriteria.MessageID | String | The message ID used when creating the remediation incident. | 
| Mimecast.Incident.SearchCriteria.FileHash | String | The file hash used when creating the remediation incident. | 
| Mimecast.Incident.SearchCriteria.StartDate | String | The start date of included messages. | 
| Mimecast.Incident.SearchCriteria.EndDate | String | The end date of included messages. | 

### mimecast-search-file-hash

***
Searches for one or more file hashes in the account. Maximum is 100.

#### Base Command

`mimecast-search-file-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hashes_to_search | List of file hashes to check if they were seen in an account. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mimecast.Hash.HashValue | String | The file hash value. | 
| Mimecast.Hash.Detected | Boolean | Whether the hash was found in the account. | 

### mimecast-update-policy

***
Updates the specified policy.

#### Base Command

`mimecast-update-policy`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                          | **Required** |
| --- |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| policy_id | The ID of the policy to update.                                                                                                                                                                                                                                                                                                                                                          | Required | 
| description | A new description for the policy.                                                                                                                                                                                                                                                                                                                                                        | Optional | 
| fromType | The sender type by which to block senders in the policy. This argument must match the fromValue argument. For example, if you specify email_domain, the fromValue must be an email domain. Possible values are: everyone, internal_addresses, external_addresses, email_domain, profile_group, address_attribute_value, individual_email_address, free_mail_domains, header_display_name. | Optional | 
| toType | The blocked receiver type by which to block receivers in the policy. This argument must match the toValue argument. For example, if you specify email_domain, the fromType must be an email domain. Possible values are: everyone, internal_addresses, external_addresses, email_domain, profile_group, individual_email_address.                                                        | Optional | 
| option | The block action. Possible values are: no_action, block_sender.                                                                                                                                                                                                                                                                                                                          | Optional | 
| fromValue | The value of the fromType argument. For example, if you specify email_domain for fromType, the fromValue must be an email domain.                                                                                                                                                                                                                                                        | Optional | 
| toValue | The value of the toType argument. For example, if you specify email_domain for toType, the toValue must be an email domain.                                                                                                                                                                                                                                                              | Optional | 
| fromPart | The part from where addresses are pulled. Possible values are: envelope_from, header_from, both.                                                                                                                                                                                                                                                                                         | Optional | 

#### Context Output

| **Path** | **Type** | **Description**                              |
| --- | --- |----------------------------------------------|
| Mimecast.Policy.ID | string | Policy ID.                                   | 
| Mimecast.Policy.Sender.Address | string | Block sender by email address value.         | 
| Mimecast.Policy.Sender.Domain | string | Block sender by domain value.                | 
| Mimecast.Policy.Sender.Group | string | Block sender by group value.                 | 
| Mimecast.Policy.Bidirectional | boolean | Whether the blocked policy is bidirectional. | 
| Mimecast.Policy.Receiver.Address | string | Block emails to receiver type address.       | 
| Mimecast.Policy.Receiver.Domain | string | Block emails to receiver type domain.        | 
| Mimecast.Policy.Receiver.Group | string | Block emails to receiver type group.         | 
| Mimecast.Policy.Fromdate | date | The policy validation start date.            | 
| Mimecast.Policy.Todate | date | The policy expiration date.                  | 
| Mimecast.Policy.Sender.Type | String | The sender type.                             | 
| Mimecast.Policy.Receiver.Type | String | The receiver type.                           | 

### mimecast-search-message

***
Searches a message

#### Base Command

`mimecast-search-message`

#### Input

| **Argument Name** | **Description**                                                                                                                     | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------------------| --- |
| search_reason | Reason for tracking the email. Possible values are: .                                                                               | Optional | 
| from_date | API start parameter. Datetime format is ISO 8601. Possible values are: .                                                            | Optional | 
| to_date | API end parameter  Datetime format ISO 8601. Possible values are: .                                                                 | Optional | 
| message_id | The internet message id of the message to track. Possible values are: .                                                             | Optional | 
| from | Part of advancedTrackAndTraceOptions object: The sending email address or domain of the messages to track. Possible values are: .   | Optional | 
| to | Part of advancedTrackAndTraceOptions object: The recipient email address or domain of the messages to track. Possible values are: . | Optional | 
| subject | Part of advancedTrackAndTraceOptions object: The subject of the messages to track. Possible values are: .                           | Optional | 
| sender_IP | Part of advancedTrackAndTraceOptions object: The source IP address of the messages to track. Possible values are: .                  | Optional | 
| route | An array of routes to filter by. Possible values are internal, outbound and inbound. Possible values are: .                         | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mimecast.SearchMessage.info | String | Info regarding the message. | 
| Mimecast.SearchMessage.id | String | The Mimecast ID of the message. Used to load more information about the message. | 
| Mimecast.SearchMessage.status | String | The status of the message. | 
| Mimecast.SearchMessage.fromEnv.emailAddress | String | The email address of the sender. | 
| Mimecast.SearchMessage.fromHdr.displayableName | String | The display name of the recipient. | 
| Mimecast.SearchMessage.fromHdr.emailAddress | String | The email address of the recipient. | 
| Mimecast.SearchMessage.to.displayableName | String | The display name of the recipient. | 
| Mimecast.SearchMessage.to.emailAddress | String | The email address of the recipient. | 
| Mimecast.SearchMessage.received | Date | The date and time the message was received by Mimecast. | 
| Mimecast.SearchMessage.subject | String | The subject of the message. | 
| Mimecast.SearchMessage.senderIP | String | The source IP address of the message. | 
| Mimecast.SearchMessage.attachments | Boolean | If the message has attachments. | 
| Mimecast.SearchMessage.route | String | The route of the message. | 
| Mimecast.SearchMessage.sent | Date | The date and time that the message was sent / processed by Mimecast. | 
| Mimecast.SearchMessage.spamScore | Number | Spam score of the email. | 
| Mimecast.SearchMessage.detectionLevel | String | Detection level of the email. | 

### mimecast-get-message-info

***
Retrieves detailed information about a specific message.

#### Base Command

`mimecast-get-message-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The Mimecast ID of the message to load. This is returned by the /api/message-finder/search endpoint. (mimecast-search-message command). Possible values are: . | Required | 
| show_recipient_info |  Default value is true. When argument is true all data from recipientInfo object is presented at command response. Possible values are: true, false. Default is true. | Optional | 
| show_delivered_message | default value is false .When argument is true all data from deliveredMessage object is presented at command response. Possible values are: true, false. Default is false. | Optional | 
| show_retention_info | Default value is true.When argument is true all data from retentionInfo object is presented at command response. Possible values are: true, false. Default is true. | Optional | 
| show_spam_info | Default value is true.When argument is true all spamInfo block is presented at command response. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.components.extension | String | Component extension type. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.components.hash | String | Component hash. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.components.mimeType | String | Component MIME type. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.components.name | String | Component name. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.components.size | Number | Component size. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.components.type | String | Component type. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.deliveryEvent | String | Description of delivery event. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.emailAddress | String | Email address of recipient. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.encryptionInfo | String | Encryption type. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.messageExpiresIn | Number | Expiration time of message. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.processingServer | String | Processing server address. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.receiptAcknowledgement | String | Recipient acknowledgement. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.remoteHost | String | Remote host address. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.remoteIp | String | Remote IP address. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.remoteServerGreeting | String | Remote server greeting. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.transmissionEnd | Date | Transmission end date. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.transmissionSize | Number | Transmission size. | 
| Mimecast.MessageInfo.deliveredMessage.deliveryMetaInfo.transmissionStart | Date |  Transmission start date. | 
| Mimecast.MessageInfo.deliveredMessage.messageInfo.fromEnvelope | String | Sender mail. (From envelope) | 
| Mimecast.MessageInfo.deliveredMessage.messageInfo.fromHeader | String | Sender mail. (From header) | 
| Mimecast.MessageInfo.deliveredMessage.messageInfo.processed | Date | Processed time and date. | 
| Mimecast.MessageInfo.deliveredMessage.messageInfo.route | String | Message route. | 
| Mimecast.MessageInfo.deliveredMessage.messageInfo.sent | Date | Message sent time and date. | 
| Mimecast.MessageInfo.deliveredMessage.messageInfo.subject | String | Message subject. | 
| Mimecast.MessageInfo.deliveredMessage.messageInfo.to | String | Recipients info. | 
| Mimecast.MessageInfo.deliveredMessage.messageInfo.transmissionInfo | String | Transmission info. | 
| Mimecast.MessageInfo.deliveredMessage.policyInfo.inherited | Boolean | Whether policy is inherited. | 
| Mimecast.MessageInfo.deliveredMessage.policyInfo.policyName | String | Policy name. | 
| Mimecast.MessageInfo.deliveredMessage.policyInfo.policyType | String | Policy type. | 
| Mimecast.MessageInfo.id | String | Message ID. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.binaryEmailSize | Number | Email size. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.components.extension | String | Component extension type. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.components.hash | String | Component hash. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.components.mimeType | String | Component MIME type. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.components.name | String | Component name. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.components.size | Number | Component size. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.components.type | String | Component type. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.encryptionInfo | String | Encryption information. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.fromEnvelope | String |  The routable email address (From envelope). | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.fromHeader | String | The routable email address (From header). | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.messageExpiresIn | Number | Expiry time of message. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.processed | Date | Message processed time. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.processingServer | String | Message processing server. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.receiptAcknowledgement | String | Recipient acknowledgement. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.receiptEvent | String | Receipt event name. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.remoteHost | String | Remote host address. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.remoteIp | String | Remote IP address. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.remoteServerGreeting | String | Remote server greeting. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.sent | Date | Message send time and date. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.spamEvent | String | Spam event name. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.subject | String | Message subject. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.to | String | Recipient info. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.transmissionEnd | Date | Transmission end date. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.transmissionInfo | String | Transmission info. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.transmissionSize | Number | Transmission size. | 
| Mimecast.MessageInfo.recipientInfo.messageInfo.transmissionStart | Date | Transmission start date. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.binaryEmailSize | Number | Email size | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.components.extension | String | Component extension type. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.components.hash | String | Component hash type. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.components.mimeType | String | Component MIME type. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.components.name | String | Component name. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.components.size | Number | Component size. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.components.type | String | Component type. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.encryptionInfo | String | Encryption information. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.messageExpiresIn | Number | Expiration time of message. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.processingServer | String | Processing server address. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.receiptAcknowledgement | String | Recipient acknowledgement. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.receiptEvent | String | Receipt event name. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.remoteHost | String | Remote host address. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.remoteIp | String | Remote IP address. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.remoteServerGreeting | String | Remote server greeting. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.spamEvent | String | Spam event name. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.transmissionEnd | Date | Transmission end date. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.transmissionSize | Number | Transmission size. | 
| Mimecast.MessageInfo.recipientInfo.recipientMetaInfo.transmissionStart | Date | Transmission start date. | 
| Mimecast.MessageInfo.retentionInfo.currentPurgeDate | Date | Current purge date and time. | 
| Mimecast.MessageInfo.retentionInfo.originalPurgeDate | Date | Original purge date and time. | 
| Mimecast.MessageInfo.retentionInfo.purgeBasedOn | String | Value that purge is based on. | 
| Mimecast.MessageInfo.retentionInfo.retentionAdjustmentDays | Number | Retention adjustment days. | 
| Mimecast.MessageInfo.spamInfo.detectionLevel | String | Spam detection level. | 
| Mimecast.MessageInfo.spamInfo.dkim.allow | Boolean | Is DomainKeys Identified Mail (DKIM) allowed. | 
| Mimecast.MessageInfo.spamInfo.dkim.info | String | DKIM info. | 
| Mimecast.MessageInfo.spamInfo.dmarc.allow | Boolean | Is Domain-based Message Authentication, Reporting & Conformance (DMARC) allowed. | 
| Mimecast.MessageInfo.spamInfo.dmarc.info | String | DMARC info. | 
| Mimecast.MessageInfo.spamInfo.greyEmail | Boolean | Is grey email allowed. | 
| Mimecast.MessageInfo.spamInfo.managedSender.allow | Boolean | Is Managed Sender allowed. | 
| Mimecast.MessageInfo.spamInfo.managedSender.info | String | Managed Sender info. | 
| Mimecast.MessageInfo.spamInfo.permittedSender.allow | Boolean | Is Permitted Sender allowed. | 
| Mimecast.MessageInfo.spamInfo.permittedSender.info | String | Permitted Sender info. | 
| Mimecast.MessageInfo.spamInfo.rbl.allow | Boolean | Is Real-time blackhole list (RBL) allowed. | 
| Mimecast.MessageInfo.spamInfo.rbl.info | String | RBL info. | 
| Mimecast.MessageInfo.spamInfo.spamScore | Number | Spam score. | 
| Mimecast.MessageInfo.spamInfo.spf.allow | Boolean | Is Sender Policy Framework (SPF) allowed. | 
| Mimecast.MessageInfo.spamInfo.spf.info | String | SPF info. | 
| Mimecast.MessageInfo.status | String | Message status. | 

### mimecast-list-held-message

***
Get information about held messages, including the reason, hold level, sender and recipients

#### Base Command

`mimecast-list-held-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| admin | Whether only results for the currently authenticated user will be returned. Possible values are: true, false. Default is false. | Optional | 
| from_date | Datetime format ISO 8601. Possible values are: . | Optional | 
| to_date | Datetime format ISO 8601. Possible values are: . | Optional | 
| value | Free text to filter results by. Possible values are: . | Optional | 
| field_name | Message fields to filter based on. Possible values are: all, subject, sender, recipient, reason_code. | Optional | 
| page_size | Number of results per page to display. Possible values are: . | Optional | 
| page | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. Possible values are: . | Optional | 
| limit | The maximum number of results to return. Possible values are: . | Optional | 

#### Context Output

| **Path**                                        | **Type** | **Description**                                                                                 |
|-------------------------------------------------|----------|-------------------------------------------------------------------------------------------------|
| Mimecast.HeldMessage.dateReceived               | Date     | The timestamp of the message transmission.                                                      | 
| Mimecast.HeldMessage.from.displayableName       | String   | The sender name.                                                                                | 
| Mimecast.HeldMessage.from.emailAddress          | String   | The sender email.                                                                               | 
| Mimecast.HeldMessage.fromHeader.displayableName | String   | The display name of the sender \(From header\).                                                 | 
| Mimecast.HeldMessage.fromHeader.emailAddress    | String   | The email address of the sender \(From header\).                                                | 
| Mimecast.HeldMessage.hasAttachments             | Boolean  | Returns true if the message contains attachments. False indicates no attachments.               | 
| Mimecast.HeldMessage.id                         | String   | The Mimecast secure ID for a message.                                                           | 
| Mimecast.HeldMessage.policyInfo                 | String   | Information or definition name triggering the message hold action.                              | 
| Mimecast.HeldMessage.reason                     | String   | The summary reason for holding the message.                                                     | 
| Mimecast.HeldMessage.reasonCode                 | String   | Reason code for holding the message.                                                            | 
| Mimecast.HeldMessage.reasonId                   | String   | Mirrors the reason field, formatted without spaces. However, reasonCode should be used instead. | 
| Mimecast.HeldMessage.route                      | String   | Direction of message being held. Possible values are: INBOUND, OUTBOUND, INTERNAL, EXTERNAL.    | 
| Mimecast.HeldMessage.size                       | Number   | The size of the message in bytes.                                                               | 
| Mimecast.HeldMessage.subject                    | String   | The message subject.                                                                            | 
| Mimecast.HeldMessage.to.displayableName         | String   | The display name of the recipient.                                                              | 
| Mimecast.HeldMessage.to.emailAddress            | String   | The email address of the recipient.                                                             | 

### mimecast-held-message-summary

***
Get counts of currently held messages for each hold reason.

#### Base Command

`mimecast-held-message-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|

#### Context Output

| **Path**                                  | **Type** | **Description**                                           |
|-------------------------------------------|----------|-----------------------------------------------------------|
| Mimecast.HeldMessageSummary.numberOfItems | Number   | The number of messages currently held for this reason.    | 
| Mimecast.HeldMessageSummary.policyInfo    | String   | The name of the policy or definition that held a message. | 

### mimecast-reject-held-message

***
Reject a currently held message.

#### Base Command

`mimecast-reject-held-message`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                  | **Required** |
| --- |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| ids | An array of Mimecast secure IDs IDs are extracted from the mimecast-list-held-message command. Possible values are: .                                                                                                            | Required | 
| message | Rejection message to be returned to the sender. Possible values are: .                                                                                                                                                           | Optional | 
| reason_type | User can choose reason . Possible values are: MESSAGE CONTAINS UNDESIRABLE CONTENT,MESSAGE CONTAINS CONFIDENTIAL INFORMATION,REVIEWER DISAPPROVES OF CONTENT,, INAPPROPRIATE COMMUNICATIONMESSAGE GOES AGAINST EMAIL POLICIES, . | Optional | 
| notify | Whether to deliver rejection notificationd. Possible values are: true, false.                                                                                                                                        | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!mimecast-reject-emessage ids="1234" message="MESSAGE CONTAINS UNDESIRABLE CONTENT" reason_type="MESSAGE CONTAINS UNDESIRABLE CONTENT" notify="True"```

#### Human Readable Output

> Held messages were rejected successfully

### mimecast-release-held-message

***
Release a currently held message.

#### Base Command

`mimecast-release-held-message`

#### Input

| **Argument Name** | **Description**                                                                                                     | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------| --- |
| id | Mimecast secure id: ID can be extracted from following command : mimecast-list-held-message. Possible values are: . | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!mimecast-release-held-message id="1234-test""```

#### Human Readable Output

> Held message with id 1234_test was released successfully

### mimecast-search-processing-message

***
Return messages currently being processed by Mimecast. Note that most of the time, no results are returned.

#### Base Command

`mimecast-search-processing-message`

#### Input

| **Argument Name** | **Description**                                                                                                                    | **Required** |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------|--------------|
| sort_order        | The method used to sort the messages. Possible values are: asc, desc.                                                              | Optional     | 
| from_date         | Datetime format ISO 8601. Possible values are: .                                                                                   | Optional     | 
| to_date           | Datetime format ISO 8601. Possible values are: .                                                                                   | Optional     | 
| value             | The search value to be used. Possible values are: .                                                                                | Optional     | 
| field_name        | The field to be searched. Possible values are: ALL, fromAddress, toAddress, subject, info, remoteIp.                               | Optional     | 
| attachments       | Whether there is an attachment in the message. Possible values are: .                                                              | Optional     | 
| route             | The message route. Possible values are: all, internal, outbound, inbound, external.                                                | Optional     | 
| page_size         | Number of results per page to display. Possible values are: .                                                                      | Optional     | 
| page              | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. Possible values are: . | Optional     | 
| limit             | The maximum number of results to return. Possible values are: .                                                                    | Optional     | 

#### Context Output

| **Path**                                                    | **Type** | **Description**                                                                                    |
|-------------------------------------------------------------|----------|----------------------------------------------------------------------------------------------------|
| Mimecast.ProcessingMessage.messages.id                      | String   | The Mimecast secure ID of the message.                                                             | 
| Mimecast.ProcessingMessage.messages.fromEnv.emailAddress    | String   | The routable email address \(From evelope\).                                                       | 
| Mimecast.ProcessingMessage.messages.fromHeader.emailAddress | String   | The routable email address \(From header\).                                                        | 
| Mimecast.ProcessingMessage.messages.to.emailAddress         | String   | The routable email address.                                                                        | 
| Mimecast.ProcessingMessage.messages.subject                 | String   | The message subject.                                                                               | 
| Mimecast.ProcessingMessage.messages.attachment              | Boolean  | The presence of an attachment in the message.                                                      | 
| Mimecast.ProcessingMessage.messages.routing                 | String   | The directional route of the message. Possible values are internal, outbound, inbound or external. | 
| Mimecast.ProcessingMessage.messages.size                    | Number   | The size of the message in bytes.                                                                  | 
| Mimecast.ProcessingMessage.messages.remoteIp                | String   | The connecting IP address.                                                                         | 
| Mimecast.ProcessingMessage.messages.attempts                | Number   | The number of processing attempts of the message.                                                  | 
| Mimecast.ProcessingMessage.messages.nextAttempt             | Date     | The date of the next process attempt for the message.                                              | 
| Mimecast.ProcessingMessage.messages.created                 | Date     | The date of the processing request creation.                                                       | 
| Mimecast.ProcessingMessage.messages.info                    | String   | Current processing status of the message.                                                          | 
| Mimecast.ProcessingMessage.messages.priority                | String   | Message proirity.                                                                                  | 

### mimecast-list-email-queues

***
Get the count of the inbound and outbound email queues at specified times.

#### Base Command

`mimecast-list-email-queues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Datetime format ISO 8601. Possible values are: . | Required | 
| to_date | Datetime format ISO 8601. Possible values are: . | Required | 

#### Context Output

| **Path** | **Type** | **Description**                                   |
| --- | --- |---------------------------------------------------|
| Mimecast.EmailQueue.inboundEmailQueue.count | Number | The number of inbound messages currently queued.  | 
| Mimecast.EmailQueue.inboundEmailQueue.date | Date | The date for the displayed number of messages.    | 
| Mimecast.EmailQueue.outboundEmailQueue.count | Number | The number of outbound messages currently queued. | 
| Mimecast.EmailQueue.outboundEmailQueue.date | Date | The date for the displayed number of messages.    | 

#### Command example

```!mimecast-list-email-queues from_date="2015-11-16T14:49:18+0000" to_date="2022-11-16T14:49:18+0000"```

#### Context Example

```json
{
  "Mimecast": {
    "EmailQueue": [
      {
        "inboundEmailQueue": [
          {
            "count": 2,
            "date": "2022-07-19T08:10:00+0000"
          },
          {
            "count": 4,
            "date": "2022-07-19T08:20:00+0000"
          },
          {
            "count": 4,
            "date": "2022-07-19T08:30:00+0000"
          },
          {
            "count": 4,
            "date": "2022-07-19T08:40:00+0000"
          }
        ]
      }
    ]
  }
}
```

#### Human Readable Output

> ### Inbound Email Queue
>| Inbound Email Queue Count | Inbound Email Queue Date |
>|---------------------------|--------------------------|
>| 2                         | 2022-07-19T08:10:00+0000 |
>| 4                         | 2022-07-19T08:20:00+0000 |
>| 4                         | 2022-07-19T08:30:00+0000 |
>| 4                         | 2022-07-19T08:40:00+0000 |
