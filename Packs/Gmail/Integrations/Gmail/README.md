Gmail API and user management (This integration replaces the Gmail functionality in the GoogleApps API and G Suite integration).
This integration was integrated and tested with version xx of Gmail

## Configure Gmail on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Gmail.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Email of user with admin privileges |  | True |
    | The content of the Service Account file |  | True |
    | Immutable Google Apps Id |  | False |
    | Events search query (e.g., "from:example@demisto.com") | Used for searching emails in the inbox. The query language follows the Gmail query specification. For example - "from:example@demisto.com is:unread". | False |
    | Events user key (e.g., example@demisto.com) | Use this to specify the email account to search for messages with the search query. By default, the integration uses the email address specified in the credentials. | False |
    | Fetch incidents |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incident type |  | False |
    | First fetch timestamp, in days. |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gmail-list-labels
***
Lists all labels in the user's mailbox.


#### Base Command

`gmail-list-labels`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GmailLabel.UserID | String | The UserID the label belongs to. | 
| GmailLabel.Name | String | The name of the label. | 
| GmailLabel.ID | String | The label ID. | 
| GmailLabel.Type | String | The label type. | 
| GmailLabel.MessageListVisibility | String | The label message list visibility. | 
| GmailLabel.LabelListVisibility | String | The label list visbility. | 

### gmail-delete-user
***
Deletes a Gmail user.


#### Base Command

`gmail-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 


#### Context Output

There is no context output for this command.
### gmail-get-tokens-for-user
***
Lists all tokens associated with a specified user. applications.


#### Base Command

`gmail-get-tokens-for-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 


#### Context Output

There is no context output for this command.
### gmail-get-user
***
Gets information for a specified user.


#### Base Command

`gmail-get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 
| projection | The subset of fields to fetch for the user. Can be: "basic": Do not include any custom fields for the user (default), "custom": Includes custom fields from schemas requested in custom-field-mask, "full": Includes all fields associated with the user. Possible values are: basic, custom, full. Default is basic. | Optional | 
| view-type-public-domain | Whether to fetch the administrator or public view of the user. Can be admin_view (default), which includes both administrator and domain-public fields; or "domain_public", which includes user fields that are publicly visible to other users in the domain. Possible values are: admin_view, domain_public. Default is admin_view. | Optional | 
| custom-field-mask | A comma separated list of schema names. All fields from these schemas are fetched. This should only be set when projection=custom. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Type | String | The account type. For example, "AD", "LocalOS", "Google", "AppleID", and so on. | 
| Account.ID | String | The unique ID for the account \(integration specific\). For AD accounts this is the Distinguished Name \(DN\). | 
| Account.DisplayName | string | The display name. | 
| Account.Gmail.Address | string | Email assigned with the current account. | 
| Account.Email.Address | String | The email address of the account. | 
| Account.Domain | String | The domain of the account. | 
| Account.Username | String | The account username in the relevant system. | 
| Account.OrganizationUnit | String | The Organization Unit \(OU\) of the account. | 
| Account.Group | String | Groups to which the account belongs \(integration specific\). For example, for AD, these are the groups in which the account is a member. | 
| Account.VisibleInDirectory | Boolean | Whether the account is visible in the directory. | 
| Account.CustomerId | String | The customer unique ID. | 

### gmail-get-user-roles
***
Retrieves a list of all Google roles for a specified user.


#### Base Command

`gmail-get-user-roles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.Role.RoleAssignmentId | String | The unique ID of the role assignment. | 
| Gmail.Role.ScopeType | String | The scope type of the role. | 
| Gmail.Role.Kind | String | The kind of the Role. | 
| Gmail.Role.OrgUnitId | String | Organization in which user was assigned. | 
| Gmail.Role.ID | String | The inner role ID. | 
| Gmail.Role.AssignedTo | String | User ID who was assigned to the role. | 

### gmail-get-attachments
***
Retrieves attachments from a sent Gmail message.


#### Base Command

`gmail-get-attachments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message-id | The ID of the message to retrieve. | Required | 
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 


#### Context Output

There is no context output for this command.
### gmail-get-mail
***
Retrieves the Gmail message sent to a specified user.


#### Base Command

`gmail-get-mail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The special value me can be used to indicate the authenticated user. | Required | 
| message-id | The ID of the message to retrieve. | Required | 
| format | The format in which to return the message. Can be: "full": Returns the full email message data with body content parsed in the payload field; the raw field is not used. (default) / "metadata": Returns only the email message ID, labels, and email headers / "minimal": Returns only the email message ID and labels; does not return the email headers, body, or payload / "raw": Returns the full email message data with body content in the raw field as a base64url encoded string; the payload field is not used. Possible values are: full, metadata, minimal, raw. Default is full. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ID | String | Inner ID of the Gmail message. | 
| Gmail.ThreadId | string | The thread ID. | 
| Gmail.Format | string | MIME type of email. | 
| Gmail.Labels | string | Labels of the specific email. | 
| Gmail.To | String | Email Address of the receiver. | 
| Gmail.From | String | Email Address of the sender. | 
| Gmail.Cc | string | Additional recipient email address \(CC\). | 
| Gmail.Bcc | string | Additional recipient email address \(BCC\). | 
| Gmail.Subject | string | Subject of the email. | 
| Gmail.Body | string | The content of the email. | 
| Gmail.Attachments | unknown | The attachments of the email. Attachments ID's are separated by ','. | 
| Gmail.Headers | unknown | All headers of the specific email \(list\). | 
| Gmail.Mailbox | string | The email mailbox. | 
| Email.To | String | The recipient of the email. | 
| Email.From | String | The sender of the email. | 
| Email.CC | String | Additional recipient email address \(CC\). | 
| Email.BCC | String | Additional recipient email address \(BCC\). | 
| Email.Format | String | The format of the email. | 
| Email.Body/HTML | String | The HTML version of the email. | 
| Email.Body/Text | String | The plain-text version of the email. | 
| Email.Subject | String | The subject of the email. | 
| Email.Headers | String | The headers of the email. | 
| Email.Attachments.entryID | Unknown | Attachments ids separated by ','. | 
| Email.Date | String | The date the email was received. | 

### gmail-search
***
Searches for Gmail records of a specified Google user.


#### Base Command

`gmail-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 
| query | Returns messages matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com rfc822msgid: is:unread". For more syntax information see "https://support.google.com/mail/answer/7190?hl=en". | Optional | 
| max-results | Maximum number of results to return. Default is 100. Maximum is 500. Can be 1 to 500, inclusive. Default is 100. | Optional | 
| fields | Enables partial responses to be retrieved, separated by commas. For more information, see https://developers.google.com/gdata/docs/2.0/basics#PartialResponse. | Optional | 
| labels-ids | Only returns messages with labels that match all of the specified label IDs in a comma separated list. | Optional | 
| page-token | Page token to retrieve a specific page of results in the list. | Optional | 
| include-spam-trash | Include messages from SPAM and TRASH in the results. (Default: false). Possible values are: False, True. Default is False. | Optional | 
| from | Specify the sender. For example, "john". | Optional | 
| to | Specify the receiver. For example, "john". | Optional | 
| subject | Words in the subject line. For example, "alert". | Optional | 
| filename | Attachments with a certain name or file type. For example, "pdf" or "report.pdf". | Optional | 
| in | Messages in any folder, including Spam and Trash. For example: shopping. | Optional | 
| after | Search for messages sent after a certain time period. For example: 2018/05/06. | Optional | 
| before | Search for messages sent before a certain time period. for example: 2018/05/09. | Optional | 
| has-attachments | Whether to search for messages sent with attachments (boolean value). Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ID | string | Inner ID of the Gmail message. | 
| Gmail.ThreadId | string | The thread ID. | 
| Gmail.Format | string | MIME type of email. | 
| Gmail.Labels | string | Labels of the specific email. | 
| Gmail.To | string | Email Address of the receiver. | 
| Gmail.From | string | Email Address of the sender. | 
| Gmail.Cc | string | Additional recipient email address \(CC\). | 
| Gmail.Bcc | string | Additional recipient email address \(BCC\). | 
| Gmail.Subject | string | Subject of the specific email. | 
| Gmail.Body | string | The content of the email. | 
| Gmail.Attachments | unknown | Attachment details. Attachments IDs are separated by ',' | 
| Gmail.Headers | unknown | All headers of a specific email \(list\). | 
| Gmail.Mailbox | string | The email mailbox. | 
| Email.To | String | The recipient of the email. | 
| Email.From | String | The sender of the email. | 
| Email.CC | String | Additional recipient email address \(CC\). | 
| Email.BCC | String | Additional recipient email address \(BCC\). | 
| Email.Format | String | The format of the email. | 
| Email.Body/HTML | String | The HTML version of the email. | 
| Email.Body/Text | String | The plain-text version of the email. | 
| Email.Subject | String | The subject of the email. | 
| Email.Headers | String | The headers of the email. | 
| Email.Attachments.entryID | Unknown | Email Attachment IDs. Separated by ',' | 
| Email.Date | String | The date the email was received. | 

### gmail-search-all-mailboxes
***
Searches the Gmail records for all Google users.


#### Base Command

`gmail-search-all-mailboxes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Returns messages matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com rfc822msgid: is:unread". For more syntax information,see "https://support.google.com/mail/answer/7190?hl=en". | Optional | 
| max-results | Maximum number of results to return. Default is 100. Maximum is 500. Acceptable values are 1 to 500, inclusive. Default is 100. | Optional | 
| fields | Enables partial responses to be retrieved in a comma separated list. For more information, see https://developers.google.com/gdata/docs/2.0/basics#PartialResponse. | Optional | 
| labels-ids | Only returns messages with labels that match all of the specified label IDs in a comma separated list. | Optional | 
| page-token | Page token to retrieve a specific page of results in the list. | Optional | 
| include-spam-trash | Includes messages from SPAM and TRASH in the results. (Default: false). Possible values are: False, True. Default is False. | Optional | 
| from | Specifies the sender. For example, "john". | Optional | 
| to | Specifies the receiver. For example, "john". | Optional | 
| subject | Words in the subject line. For example, "alert". | Optional | 
| filename | Attachments with a certain name or file type. For example, "pdf" or "report.pdf". | Optional | 
| in | Messages in any folder, including Spam and Trash. For example, shopping. | Optional | 
| after | Search for messages sent after a certain time period. For example, 2018/05/06. | Optional | 
| before | Search for messages sent before a certain time period. For example, 2018/05/09. | Optional | 
| has-attachments | Whether to search for messages sent with attachments. Possible values are: False, True. | Optional | 
| show-only-mailboxes | Whether to return only mailboxes which contain the email. Default is "False". Possible values are: false, true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ID | string | Inner ID of the Gmail message. | 
| Gmail.ThreadId | string | The thread ID. | 
| Gmail.Format | string | MIME type of the email. | 
| Gmail.Labels | string | Labels of a specific email. | 
| Gmail.To | string | Email Address of the receiver. | 
| Gmail.From | string | Email Address of the sender. | 
| Gmail.Cc | string | Additional recipient email address \(CC\). | 
| Gmail.Bcc | string | Additional recipient email address \(BCC\). | 
| Gmail.Subject | string | Subject of the specific email. | 
| Gmail.Body | string | The content of the email. | 
| Gmail.Attachments | unknown | The attachments of the email. IDs are separated by ','. | 
| Gmail.Headers | unknown | All headers of specific mail \(list\). | 
| Gmail.Mailbox | string | The Gmail Mailbox. | 
| Email.To | String | The recipient of the email. | 
| Email.From | String | The sender of the email. | 
| Email.CC | String | Additional recipient email address \(CC\). | 
| Email.BCC | String | Additional recipient email address \(BCC\). | 
| Email.Format | String | The format of the email. | 
| Email.Body/HTML | String | The HTML version of the email. | 
| Email.Body/Text | String | The plain-text version of the email. | 
| Email.Subject | String | The subject of the email. | 
| Email.Headers | String | The headers of the email. | 
| Email.Attachments.entryID | Unknown | Email Attachments. IDs are separated by ','. | 
| Email.Date | String | The date the email was received. | 

### gmail-list-users
***
Lists all Google users in a domain.


#### Base Command

`gmail-list-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| projection | The subset of fields to fetch for the user. Can be "basic": Do not include any custom fields for the user. (default), "custom": Include custom fields from schemas requested in customFieldMask, "full": Include all fields associated with this user. Possible values are: basic, custom, full. | Optional | 
| domain | The domain name. Use this field to get fields from only one domain. To return all domains for a customer account, use the customer query parameter. | Optional | 
| customer | The unique ID for the customers Google account. Default is the value specified in the integration configuration. For a multi-domain account, to fetch all groups for a customer, use this field instead of domain. | Optional | 
| max-results | Maximum number of results to return. Default is 100. Maximum is 500. Can be 1 to 500, inclusive. | Optional | 
| custom-field-mask | A comma-separated list of schema names. All fields from these schemas are fetched. Must be set when projection=custom. | Optional | 
| query | Query string search. Should be of the form "". Complete documentation is at https://developers.google.com/admin-sdk/directory/v1/guides/search-users. | Optional | 
| show-deleted | If true, retrieves the list of deleted users. Default is false. Possible values are: False, True. | Optional | 
| sort-order | How to sort out results. Can be ASCENDING/DESCENDING. Possible values are: ASCENDING, DESCENDING. | Optional | 
| token | Token to authorize and authenticate the action. | Optional | 
| view-type-public-domain | Whether to fetch either the administrator or public view of the user. Can be admin_view (default), which includes both administrator and domain-public fields or "domain_public"(includes fields for the user that are publicly visible to other users in the domain). Possible values are: admin_view, domain_public. Default is admin_view. | Optional | 
| page-token | Token to specify next page in the list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Type | String | The account type. For example, "AD", "LocalOS", "Google", "AppleID", and so on. | 
| Account.ID | String | The unique ID for the account \(integration specific\). For AD accounts this is the Distinguished Name \(DN\). | 
| Account.DisplayName | String | The display name. | 
| Account.Gmail.Address | string | Email assigned with the current account. | 
| Account.Email.Adderss | String | The email address of the account. | 
| Account.Groups | String | Groups to which the account belongs \(integration specific\). For example, for AD these are the groups in which the account is member. | 
| Account.Domain | String | The domain of the account. | 
| Account.Username | String | The username of the account. | 
| Account.OrganizationUnit | String | The Organization Unit \(OU\) of the account. | 

### gmail-revoke-user-role
***
Revokes a role for a specified Google user.


#### Base Command

`gmail-revoke-user-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The special value me can be used to indicate the authenticated user. | Optional | 
| role-assignment-id | The immutable ID of the role assignment. | Required | 


#### Context Output

There is no context output for this command.
### gmail-create-user
***
Creates a new Gmail user.


#### Base Command

`gmail-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The user's primary email address. The primary email address must be unique and cannot be an alias of another user. | Required | 
| first-name | The user's first name. | Required | 
| family-name | The user's last name. | Required | 
| password | Stores the password for the user account. A password can contain any combination of ASCII characters. A minimum of 8 characters is required. The maximum length is 100 characters. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Type | String | The account type. For example, "AD", "LocalOS", "Google", "AppleID", and so on. | 
| Account.ID | String | The unique ID for the account \(integration specific\). For AD accounts this is the Distinguished Name \(DN\). | 
| Account.DisplayName | string | The display name. | 
| Account.Gmail.Address | string | Email assigned with the current account. | 
| Account.Email.Address | String | The email address of the account. | 
| Account.Username | String | The username of the account. | 
| Account.Groups | String | Groups to which the account belongs \(integration specific\). For example, for AD these are groups in which the account is a member. | 
| Account.Domain | String | The domain of the account. | 
| Account.OrganizationUnit | String | The Organization Unit \(OU\) of the account. | 

### gmail-delete-mail
***
Deletes an email in the user's mailbox.


#### Base Command

`gmail-delete-mail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The special value me can be used to indicate the authenticated user. | Required | 
| message-id | The ID of the message to delete. | Required | 
| permanent | Whether to delete the email permanently or move it to trash (default). Possible values are: False, True. | Optional | 


#### Context Output

There is no context output for this command.
### gmail-get-thread
***
Returns all messages in a thread.


#### Base Command

`gmail-get-thread`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The special value me can be used to indicate the authenticated user. | Required | 
| thread-id | The ID of the thread to retrieve. | Required | 
| format | The format in which to return the message. Can be: "full": Returns the full email message data with body content parsed in the payload field; the raw field is not used. (default) / "metadata": Returns only email message ID, labels, and email headers / "minimal": Returns only email message ID and labels; does not return the email headers, body, or payload / "raw": Returns the full email message data with body content in the raw field as a base64url encoded string; the payload field is not used. Possible values are: full, metadata, minimal, raw. Default is full. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ID | string | Inner ID of the Gmail message. | 
| Gmail.ThreadId | string | The thread ID. | 
| Gmail.Format | string | MIME type of email. | 
| Gmail.Labels | string | Labels of the specific email. | 
| Gmail.To | string | Email Address of the receiver. | 
| Gmail.From | string | Email Address of the sender. | 
| Gmail.Cc | string | Additional recipient email address \(CC\). | 
| Gmail.Bcc | string | Additional recipient email address \(BCC\). | 
| Gmail.Subject | string | Subject of a specific email. | 
| Gmail.Body | string | The content of the email. | 
| Gmail.Attachments | unknown | The attachments of the email. IDs are separated by ','. | 
| Gmail.Headers | unknown | All headers of the specific email \(list\). | 
| Gmail.Mailbox | string | The Gmail Mailbox. | 
| Email.To | String | The recipient of the email. | 
| Email.From | String | The sender of the email. | 
| Email.CC | String | Additional recipient email address \(CC\). | 
| Email.BCC | String | Additional recipient email address \(BCC\). | 
| Email.Format | String | The format of the email. | 
| Email.Body/HTML | String | The HTML version of the email. | 
| Email.Body/Text | String | The plain-text version of the email. | 
| Email.Subject | String | The subject of the email. | 
| Email.Headers | String | The headers of the email. | 
| Email.Attachments.entryID | Unknown | Email Attachments. IDs are separated by ','. | 
| Email.Date | String | The date the email was received. | 

### gmail-move-mail
***
Moves an email to a different folder.


#### Base Command

`gmail-move-mail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The special value me can be used to indicate the authenticated user. | Required | 
| message-id | The ID of the message to retrieve. | Required | 
| add-labels | Comma-separated list of labels to add to the email. | Optional | 
| remove-labels | Comma separated list of labels to remove from the email. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ID | string | Inner ID of the Gmail message. | 
| Gmail.ThreadId | string | The thread ID. | 
| Gmail.Format | string | MIME type of email. | 
| Gmail.Labels | string | Labels of the specific email. | 
| Gmail.To | string | Gmail address of the receiver. | 
| Gmail.From | string | Gmail address of the sender. | 
| Gmail.Cc | string | Additional recipient email address \(CC\). | 
| Gmail.Bcc | string | Additional recipient email address \(BCC\). | 
| Gmail.Subject | string | Subject of the specific email. | 
| Gmail.Body | string | The content of the email. | 
| Gmail.Attachments | unknown | The attachments of the email. IDs are separated by ','. | 
| Gmail.Headers | unknown | All headers of the specific email \(list\). | 
| Gmail.Mailbox | string | The Gmail mailbox. | 
| Email.To | String | The recipient of the email. | 
| Email.From | String | The sender of the email. | 
| Email.CC | Unknown | Additional recipient email address \(CC\). | 
| Email.BCC | Unknown | Additional recipient email address \(BCC\). | 
| Email.Format | String | The format of the email. | 
| Email.Body/HTML | String | The HTML version of the email. | 
| Email.Body/Text | String | The plain-text version of the email. | 
| Email.Subject | String | The subject of the email. | 
| Email.Headers | String | The headers of the email. | 
| Email.Attachments.entryID | Unknown | Email attachments. IDs are separated by ','. | 
| Email.Date | String | The date the email was received. | 

### gmail-move-mail-to-mailbox
***
Moves an email to a different mailbox.


#### Base Command

`gmail-move-mail-to-mailbox`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src-user-id | The source user's email address. The special value me can be used to indicate the authenticated user. | Required | 
| message-id | The ID of the message to retrieve. | Required | 
| dst-user-id | The destination user's email address. The me special value can be used to indicate the authenticated user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ID | string | Inner ID of the Gmail message. | 
| Gmail.ThreadId | string | The thread ID. | 
| Gmail.Format | string | MIME type of email. | 
| Gmail.Labels | string | Labels of the specific email. | 
| Gmail.To | string | Gmail address of the receiver. | 
| Gmail.From | string | Gmail address of the sender. | 
| Gmail.Cc | string | Additional recipient email address \(CC\). | 
| Gmail.Bcc | string | Additional recipient email address \(BCC\). | 
| Gmail.Subject | string | Subject of the specific email. | 
| Gmail.Body | string | The content of the email. | 
| Gmail.Attachments | unknown | The attachments of the email. IDs are separated by ','. | 
| Gmail.Headers | unknown | All headers of specific the email \(list\). | 
| Gmail.Mailbox | string | The Gmail mailbox. | 
| Email.To | String | The recipient of the email. | 
| Email.From | String | The sender of the email. | 
| Email.CC | String | Additional recipient email address \(CC\). | 
| Email.BCC | String | Additional recipient email address \(BCC\). | 
| Email.Format | String | The format of the email. | 
| Email.Body/HTML | String | The HTML version of the email. | 
| Email.Body/Text | String | The plain-text version of the email. | 
| Email.Subject | String | The subject of the email. | 
| Email.Headers | String | The headers of the email. | 
| Email.Attachments.entryID | Unknown | Emails attachments. IDs are separated by ','. | 
| Email.Date | String | The date the email was received. | 

### gmail-add-delete-filter
***
Adds a rule for email deletion by address.


#### Base Command

`gmail-add-delete-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The me special value can be used to indicate the authenticated user. | Required | 
| email-address | Email address in which to block messages. | Required | 


#### Context Output

There is no context output for this command.
### gmail-add-filter
***
Add a new filter.


#### Base Command

`gmail-add-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The me special value can be used to indicate the authenticated user. | Required | 
| from | The sender's display name or email address. | Optional | 
| to | The recipient's display name or email address. Includes recipients in the "to", "cc", and "bcc" header fields. You can use the local part of the email address. For example, "example" and "example@" both match "example@gmail.com". This field is case-insensitive. | Optional | 
| subject | The email subject. | Optional | 
| query | Returns messages matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com is:unread". | Optional | 
| has-attachments | Whether the message has any attachments. | Optional | 
| size | The size of the entire RFC822 message in bytes, including all headers and attachments. | Optional | 
| add-labels | Comma-separated list of labels to add to the message. | Optional | 
| remove-labels | Comma-separated list of labels to remove from the message. | Optional | 
| forward | Email address that the message is to be forwarded. The email needs to be configured as a forwarding address, see https://support.google.com/mail/answer/10957?hl=en#null. | Optional | 
| size-comparison | The message size in bytes compared to the size field. Possible values are: larger, smaller. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.Filter.ID | String | Filter ID. | 
| Gmail.Filter.Mailbox | String | Mailbox containing the filter. | 
| Gmail.Filter.Criteria | Unknown | Filter Criteria. | 
| Gmail.Filter.Action | Unknown | Filter Action. | 

### gmail-list-filters
***
List all filters in a user's mailbox.


#### Base Command

`gmail-list-filters`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | User's email address. The "me" special value can be used to indicate the authenticated user. | Required | 
| limit | Limit of the results list. Default is 100. | Optional | 
| address | List filters associated with the email address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.Filter.ID | String | Filter ID. | 
| Gmail.Filter.Mailbox | String | Mailbox containing the filter. | 
| Gmail.Filter.Criteria | Unknown | Filter Criteria. | 
| Gmail.Filter.Action | Unknown | Filter Action. | 

### gmail-remove-filter
***
Removes a Filter.


#### Base Command

`gmail-remove-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | User's email address. The "me" special value can be used to indicate the authenticated user. | Required | 
| filter_ids | Comma separated list of filter IDs (can be retrieve using `gmail-list-filters` command). | Required | 


#### Context Output

There is no context output for this command.
### gmail-hide-user-in-directory
***
Hide a user's contact information, such as email address, profile information in the Global Directory.


#### Base Command

`gmail-hide-user-in-directory`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 
| visible-globally | Whether to hide the user's visibility in the Global Directory. Can be False to hide the user, True to show the user in the directory (default). Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Type | String | The account type. For example, "AD", "LocalOS", "Google", "AppleID", and so on. | 
| Account.ID | String | The unique ID for the account \(integration specific\). For AD accounts this is the Distinguished Name \(DN\). | 
| Account.DisplayName | String | The display name. | 
| Account.Email.Address | String | The email address of the account. | 
| Account.Gmail.Address | Unknown | Email assigned with current account. | 
| Account.Domain | String | The domain of the account. | 
| Account.Username | String | The username of the account. | 
| Account.OrganizationUnit | String | The Organization Unit \(OU\) of the account. | 
| Account.VisibleInDirectory | Boolean | Is the Account visible in the Global Directory. | 
| Account.Groups | String | Groups in which the account belongs \(integration specific\). For example, for AD these are groups of which the account is memberOf. | 

### gmail-set-password
***
Sets the password for the user.


#### Base Command

`gmail-set-password`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The special value me can be used to indicate the authenticated user. | Required | 
| password | String formatted password for the user. Depends on the Password Policy of the Organization. | Required | 


#### Context Output

There is no context output for this command.
### gmail-get-autoreply
***
Returns the auto-reply message set for the user-account.


#### Base Command

`gmail-get-autoreply`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The special value me can be used to indicate the authenticated user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Gmail.AutoReply.EnableAutoReply | Boolean | Flag that controls whether Gmail automatically replies to messages. | 
| Account.Gmail.AutoReply.ResponseBody | String | Response body in plain text format. | 
| Account.Gmail.AutoReply.ResponseSubject | String | Optional text to add to the subject line in vacation responses. To enable auto-replies, the response subject or the response body must not be empty. | 
| Account.Gmail.AutoReply.RestrictToContact | String | Flag that determines whether responses are sent to recipients who are not in the user's list of contacts. | 
| Account.Gmail.AutoReply.RestrictToDomain | String | Flag that determines whether responses are sent to recipients who are outside of the user's domain. This feature is only available for G Suite users. | 
| Account.Gmail.Address | String | Email assigned with the current account. | 

### gmail-set-autoreply
***
Sets the auto-reply for the user. Note: If the body is not set, the current body will be deleted.


#### Base Command

`gmail-set-autoreply`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value me can be used to indicate the authenticated user. | Required | 
| enable-autoReply | Whether Gmail automatically replies to messages. Boolean. Set to true to automatically reply (default). Possible values are: true, false. Default is true. | Optional | 
| response-subject | Optional text to add to the subject line in vacation responses. To enable auto-replies, either the response subject or the response body must not be empty. | Optional | 
| response-body | Response body in plain text format. | Optional | 
| response-body-entry-id | Set the away/vacation message by passing a War Room entryID of the file for the given user. | Optional | 
| start-time | Set a start date for the vacation message to be enabled for the given user. The valid format is YYYY-MM-DD or Epoch time in milliseconds. | Optional | 
| end-time | Set an end date for the vacation message to be enabled for the given user. The valid format is YYYY-MM-DD or Epoch time in milliseconds. | Optional | 
| contacts-only | Whether to send away/vacation messages to users in the contact list when set to true. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| domain-only | Whether to prevent sending away/vacation messages to recipients who are outside of the user's domain when set to true. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| response-body-type | Whether message response body type is text or HTML. Default is "Text". Possible values are: HTML, Text. Default is Text. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Gmail.AutoReply.EnableAutoReply | Boolean | Flag that controls whether Gmail automatically replies to messages. | 
| Account.Gmail.AutoReply.ResponseBody | String | Response body in plain text format. | 
| Account.Gmail.AutoReply.ResponseSubject | String | Optional text to add to the subject line in vacation responses. To enable auto-replies, either the response subject or the response body must not be empty. | 
| Account.Gmail.AutoReply.RestrictToContact | String | Determines whether responses are sent to recipients who are not in the user's list of contacts. | 
| Account.Gmail.AutoReply.RestrictToDomain | String | Determines whether responses are sent to recipients who are outside of the user's domain. This feature is only available for G Suite users. | 
| Account.Gmail.Address | String | Email assigned with the current account. | 
| Account.Gmail.AutoReply.ResponseBodyHtml | String | Response body in HTML format. | 
| Account.Gmail.AutoReply.StartTime | Number | Start time for sending auto-replies. | 
| Account.Gmail.AutoReply.EndTime | Number | End time for sending auto-replies. | 

### gmail-delegate-user-mailbox
***
Adds a delegate to the mailbox, without sending any verification email. The delegate user must be a member of the same G Suite organization as the delegator user and must be added using their primary email address, and not an email alias.


#### Base Command

`gmail-delegate-user-mailbox`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 
| delegate-email | The email address of the delegate. | Required | 


#### Context Output

There is no context output for this command.
### send-mail
***
Sends mail using Gmail.


#### Base Command

`send-mail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Email addresses of the receiver. | Required | 
| from | Email address of the sender. | Optional | 
| body | The contents (body) of the email to be sent in plain text. | Optional | 
| subject | Subject for the email to be sent. | Required | 
| attachIDs | A comma-separated list of IDs of War Room entries that contain the files that need be attached to the email. | Optional | 
| cc | Additional recipient email address (CC). | Optional | 
| bcc | Additional recipient email address (BCC). | Optional | 
| htmlBody | The contents (body) of the email to be sent in HTML format. | Optional | 
| replyTo | Address that needs to be used to reply to the message. | Optional | 
| attachNames | A comma-separated list of new names to rename attachments corresponding to the order that they were attached to the email.<br/>        Examples - To rename first and third file attachNames=new_fileName1,,new_fileName3<br/>        To rename second and fifth files attachNames=,new_fileName2,,,new_fileName5. | Optional | 
| attachCIDs | A comma-separated list of CID images to embed attachments inside the email. | Optional | 
| transientFile | Textual name for an attached file. Multiple files are supported as a<br/>        comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test<br/>        2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz"). | Optional | 
| transientFileContent | Content for the attached file. Multiple files are supported as a comma-separated<br/>        list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test<br/>        2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz"). | Optional | 
| transientFileCID | CID image for an attached file to include within the email body. Multiple files are<br/>        supported as comma-separated list. (e.g. transientFile="t1.txt,temp.txt,t3.txt"<br/>        transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz"). | Optional | 
| additionalHeader | A CSV list of additional headers in the format: headerName=headerValue. For example: "headerName1=headerValue1,headerName2=headerValue2". | Optional | 
| templateParams | 'Replaces {varname} variables with values from this parameter. Expected<br/>       values are in the form of a JSON document. For example, {"varname" :{"value" "some<br/>       value", "key": "context key"}}. Each var name can either be provided with<br/>       the value or a context key to retrieve the value.<br/>       Note that only context data is accessible for this argument, while incident fields are not.'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.SentMail.ID | String | The immutable ID of the message. | 
| Gmail.SentMail.Labels | String | List of IDs of labels applied to this message. | 
| Gmail.SentMail.ThreadId | String | The ID of the thread in which the message belongs. | 
| Gmail.SentMail.To | String | The recipient of the email. | 
| Gmail.SentMail.From | Unknown | The sender of the email. | 
| Gmail.SentMail.Cc | String | Additional recipient email address \(CC\). | 
| Gmail.SentMail.Bcc | String | Additional recipient email address \(BCC\). | 
| Gmail.SentMail.Subject | String | The subject of the email. | 
| Gmail.SentMail.Body | Unknown | The plain-text version of the email. | 
| Gmail.SentMail.MailBox | String | The mailbox from which the mail was sent. | 

### reply-mail
***
Replies to a mail using Gmail.


#### Base Command

`reply-mail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Email addresses of the recipients. | Required | 
| from | Email address of the sender. | Optional | 
| body | The contents (body) of the email to be sent in plain text. | Optional | 
| subject | Subject of the email to be sent. Should be the same as the subject of the email you are replying to in order for the reply to be a part of the same conversation. | Required | 
| inReplyTo | A comma-separated list of message IDs to reply to. | Required | 
| references | A comma-separated list of message IDs to refer to. | Optional | 
| attachIDs | A comma-separated list of IDs of War Room entries that contain the files that need to be attached to the email. | Optional | 
| cc | Additional recipient email addresses (CC). | Optional | 
| bcc | Additional recipient email addresses (BCC). | Optional | 
| htmlBody | The contents (body) of the email to be sent in HTML format. | Optional | 
| replyTo | Address that needs to be used to reply to the message. | Optional | 
| attachNames | A comma-separated list of new names used to rename attachments corresponding to the order in which they were attached to the email.<br/>        Examples - To rename the first and third file: attachNames=new_fileName1,,new_fileName3<br/>        To rename the second and fifth files: attachNames=,new_fileName2,,,new_fileName5. | Optional | 
| attachCIDs | A comma-separated list of CID images to embed as attachments inside the email. | Optional | 
| transientFile | Textual name for an attached file. Multiple files are supported as a comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz"). | Optional | 
| transientFileContent | Content for the attached file. Multiple files are supported as a comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz"). | Optional | 
| transientFileCID | CID image for an attached file to include within the email body. Multiple files are supported as a comma-separated list. (e.g. transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz"). | Optional | 
| additionalHeader | A comma-separated list of additional headers in the format: headerName=headerValue. For example: "headerName1=headerValue1,headerName2=headerValue2". | Optional | 
| templateParams | 'Replaces {varname} variables with values from this parameter. Expected values are in the form of a JSON document. For example, {"varname" :{"value" "some value", "key": "context key"}}. Each var name can either be provided with the value or a context key to retrieve the value. Note that only context data is accessible for this argument, while incident fields are not.'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.SentMail.ID | String | The immutable ID of the message. | 
| Gmail.SentMail.Labels | String | List of IDs of the labels applied to this message. | 
| Gmail.SentMail.ThreadId | String | The ID of the thread in which the message belongs. | 
| Gmail.SentMail.To | String | The recipients of the email. | 
| Gmail.SentMail.From | Unknown | The sender of the email. | 
| Gmail.SentMail.Cc | String | Additional recipient email addresses \(CC\). | 
| Gmail.SentMail.Bcc | String | Additional recipient email addresses \(BCC\). | 
| Gmail.SentMail.Subject | String | The subject of the email. | 
| Gmail.SentMail.Body | Unknown | The plain-text version of the email. | 
| Gmail.SentMail.MailBox | String | The mailbox from which the mail was sent. | 

### gmail-remove-delegated-mailbox
***
Removes a delegate from the mailbox, without sending any verification email. The delegate user must be a member of the same G Suite organization as the delegator user using their primary email address, and not an email alias.


#### Base Command

`gmail-remove-delegated-mailbox`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | The user's email address. The "me" special value can be used to indicate the authenticated user. | Required | 
| removed-mail | The email address to remove from delegation. | Required | 


#### Context Output

There is no context output for this command.
### gmail-get-role
***
Get details of a specific role.


#### Base Command

`gmail-get-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role-id | The ID of the role. Can be retrieved using the get-user-roles command. | Required | 
| customer-id | Immutable Google Apps ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.Role.ETag | String | The ETag of the resource. | 
| Gmail.Role.IsSuperAdminRole | Boolean | Indicates whether the role is a super admin role or not. | 
| Gmail.Role.IsSystemRole | Boolean | Indicates whether the role is a pre-defined system role or not. | 
| Gmail.Role.Kind | String | The kind of the Role. | 
| Gmail.Role.Description | String | The description of the role. | 
| Gmail.Role.ID | String | The ID of the role. | 
| Gmail.Role.Name | String | The name of the role. | 
| Gmail.Role.Privilege.ServiceID | String | The ID of the service this privilege is for. | 
| Gmail.Role.Privilege.Name | String | The name of the privilege. | 

### gmail-forwarding-address-add
***
Creates a forwarding address. If ownership verification is required, a message will be sent to the recipient and the resource's verification status will be set to pending; otherwise, the resource will be created with verification status set to accepted. This method is only available to service account clients that have been delegated domain-wide authority. The special value "me" can be used to indicate the authenticated user.


#### Base Command

`gmail-forwarding-address-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| forwarding_email | A comma-separated list of emails addresses to which messages can be forwarded. | Required | 
| user_id | The user email address or the user id, use the !gmail-list-users command, in order to get the user id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ForwardingAddress.forwardingEmail | String | An email address to which messages can be forwarded. | 
| Gmail.ForwardingAddress.userId | String | The user's email address. | 
| Gmail.ForwardingAddress.verificationStatus | String | Indicates whether this address has been verified and is usable for forwarding. | 

#### Command example
```!gmail-forwarding-address-add forwarding_email="admin@demistodev.com" user_id="me"```
#### Context Example
```json
{
    "Gmail": {
        "ForwardingAddress": {
            "forwardingEmail": "admin@demistodev.com",
            "userId": "me",
            "verificationStatus": "accepted"
        }
    }
}
```

#### Human Readable Output

>### Forwarding addresses results for "me":
>|forwardingEmail|userId|verificationStatus|
>|---|---|---|
>| admin@demistodev.com | me | accepted |


### gmail-forwarding-address-update
***
Updates the auto-forwarding setting for the specified account. A verified forwarding address must be specified when auto-forwarding is enabled.


#### Base Command

`gmail-forwarding-address-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| disposition | The state that a message should be left in after it has been forwarded. Possible values are: archive, leaveInInbox, markRead, trash. | Optional | 
| forwarding_email | A comma-separated list of emails addresses to which messages can be forwarded. | Required | 
| user_id | The user email address or the user id, use the !gmail-list-users command, in order to get the user id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ForwardingAddress.forwardingEmail | String | An email address to which messages can be forwarded. | 
| Gmail.ForwardingAddress.userId | String | The user's email address. | 
| Gmail.ForwardingAddress.verificationStatus | String | Indicates whether this address has been verified and is usable for forwarding. | 
| Gmail.ForwardingAddress.Disposition | String | The state that a message should be left in after it has been forwarded. | 
| Gmail.ForwardingAddress.Enabled | Boolean | Indicates whether all incoming mail is automatically forwarded to another address. | 

#### Command example
```!gmail-forwarding-address-update forwarding_email="admin@demistodev.com" user_id="me" disposition="archive"```
#### Context Example
```json
{
    "Gmail": {
        "ForwardingAddress": {
            "disposition": "archive",
            "emailAddress": "admin@demistodev.com",
            "enabled": true,
            "userId": "me"
        }
    }
}
```

#### Human Readable Output

>### Forwarding addresses update results for "me":
>|userId|disposition|enabled|
>|---|---|---|
>| me | archive | true |


### gmail-send-as-add
***
Creates a custom "from" send-as alias. If an SMTP MSA is specified, Gmail will attempt to connect to the SMTP service to validate the configuration before creating the alias. If ownership verification is required for the alias, a message will be sent to the email address and the resource's verification status will be set to pending; otherwise, the resource will be created with verification status set to accepted. If a signature is provided, Gmail will sanitize the HTML before saving it with the alias.

This command is only available to service account clients who have been delegated domain-wide authority.


#### Base Command

`gmail-send-as-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user's email address. | Required | 
| send_as_email | The email address that appears in the "From:" header for email sent using this alias. | Required | 
| display_name | A name that appears in the "From:" header for mail sent using this alias. For custom "from" addresses, when this is empty, Gmail will populate the "From:" header with the name that is used for the primary address associated with the account. If the admin disabled the ability for users to update their name format, requests to update this field for the primary login will silently fail. | Optional | 
| signature | An optional HTML signature that is included in messages composed with this alias in the Gmail web UI. | Optional | 
| reply_to_address | An optional email address that is included in a "Reply-To:" header for email sent using this alias. If this is empty, Gmail will not generate a "Reply-To:" header. | Optional | 
| is_default | Whether this address is selected as the default "From:" address in situations such as composing a new message or sending a vacation auto-reply. Every Gmail account has exactly one default send-as address, so the only legal value that clients may write to this field is true. Changing this from false to true for an address will result in this field becoming false for the other previous default address. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| treat_as_alias | Whether Gmail should treat this address as an alias for the user's primary email address. This setting only applies to custom "from" aliases. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| smtp_host | The hostname of the SMTP service. Required for SMTP configuration. | Optional | 
| smtp_port | The port of the SMTP service. Required for SMTP configuration. | Optional | 
| smtp_username | The username that will be used for authentication with the SMTP service. This is a write-only field that can be specified in requests to create or update SendAs settings. | Optional | 
| smtp_password | The password that will be used for authentication with the SMTP service. This is a write-only field that can be specified in requests to create or update SendAs settings. | Optional | 
| smtp_securitymode | The protocol that will be used to secure communication with the SMTP service. Required for SMTP configuration.<br/><br/>Available Options:<br/>SECURITY_MODE_UNSPECIFIED - Unspecified security mode.<br/><br/>NONE - Communication with the remote SMTP service is unsecured. Requires port 25.<br/><br/>SSL - Communication with the remote SMTP service is secured using SSL.<br/><br/>STARTTLS - Communication with the remote SMTP service is secured using STARTTLS. Possible values are: SECURITY_MODE_UNSPECIFIED, NONE, SSL, STARTTLS. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.SendAs.userId | String | The user's email address. | 
| Gmail.SendAs.sendAsEmail | String | The updated send-as alias. | 
| Gmail.SendAs.signature | String | An optional HTML signature that is included in messages composed with this alias in the Gmail web UI. | 
| Gmail.SendAs.isPrimary | Boolean | Whether this address is the primary address used to login to the account. | 
| Gmail.SendAs.isDefault | Boolean | Whether this address is selected as the default "From:" address in situations. | 
| Gmail.SendAs.treatAsAlias | Boolean | Whether Gmail should treat this address as an alias for the user's primary email address. | 
| Gmail.SendAs.smtpMsaHost | String | The hostname of the SMTP service. | 
| Gmail.SendAs.smtpMsaPort | String | The port of the SMTP service. | 
| Gmail.SendAs.smtpMsaSecurityMode | String | The protocol that will be used to secure communication with the SMTP service. | 
| Gmail.SendAs.verificationStatus | String | Indicates whether this address has been verified for use as a send-as alias. | 
| Gmail.SendAs.replyToAddress | String | A name that appears in the "From:" header for email sent using this alias. | 

### gmail-forwarding-address-get
***
Gets the specified forwarding address or a list of the forwarding addresses for the specified account.


#### Base Command

`gmail-forwarding-address-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user email address or the user id, use the !gmail-list-users command, in order to get the user id. | Required | 
| forwarding_email | The forwarding address to be retrieved. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ForwardingAddress.userId | String | The user email address or the user id, use the \!gmail-list-users command, in order to get the user id. | 
| Gmail.ForwardingAddress.forwardingEmail | String | An email address to which messages can be forwarded. | 

#### Command example
```!gmail-forwarding-address-get forwarding_email="admin@demistodev.com" user_id="me"```
#### Context Example
```json
{
    "Gmail": {
        "ForwardingAddress": {
            "forwardingEmail": "admin@demistodev.com",
            "userId": "me",
            "verificationStatus": "accepted"
        }
    }
}
```

#### Human Readable Output

>### Get forwarding address for: "me"
>|forwardingEmail|verificationStatus|
>|---|---|
>| admin@demistodev.com | accepted |


### gmail-forwarding-address-remove
***
Deletes the specified forwarding address and revokes any verification that may have been required. This method is only available to service account clients that have been delegated domain-wide authority.


#### Base Command

`gmail-forwarding-address-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user email address or the user id, use the !gmail-list-users command, in order to get the user id. | Required | 
| forwarding_email | The forwarding address to be retrieved. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!gmail-forwarding-address-remove forwarding_email="admin@demistodev.com" user_id="me"```
#### Human Readable Output

>Forwarding address "admin@demistodev.com" for "me" was deleted successfully .

### gmail-forwarding-address-list
***
Lists the forwarding addresses for the specified account.


#### Base Command

`gmail-forwarding-address-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user email address or the user id, use the !gmail-list-users command, in order to get the user id. The special value "me" can be used to indicate the authenticated user. | Required | 
| limit | The maximum number of addresses to return. The default value is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gmail.ForwardingAddress.forwardingEmail | String | An email address to which messages can be forwarded. | 
| Gmail.ForwardingAddress.verificationStatus | String | Indicates whether this address has been verified and is usable for forwarding. | 

#### Command example
```!gmail-forwarding-address-list user_id="me"```
#### Context Example
```json
{
    "Gmail": {
        "ForwardingAddress": [
            {
                "forwardingEmail": "admin@demistodev.com",
                "userId": "me",
                "verificationStatus": "accepted"
            },
            {
                "forwardingEmail": "test1@gmail.com",
                "userId": "me",
                "verificationStatus": "accepted"
            },
            {
                "forwardingEmail": "test2@gmail.com",
                "userId": "me",
                "verificationStatus": "accepted"
            },
            {
                "forwardingEmail": "test3@gmail.com",
                "userId": "me",
                "verificationStatus": "accepted"
            },
        ]
    }
}
```

#### Human Readable Output

>### Forwarding addresses list for: "me"
>|forwardingEmail|verificationStatus|
>|---|---|
>| admin@demistodev.com | accepted |
>| test1@gmail.com | accepted |
>| test2@gmail.com | accepted |
>| test3@gmail.com | accepted |


