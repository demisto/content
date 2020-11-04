Use the Gmail integration to search and process emails in the organizational Gmail mailboxes.

This integration replaces the Gmail functionality in the GoogleApps API and G Suite integration. 

Prerequisites
-------------

There are several procedures you have to perform in Google before configuring the integration on Demisto.

*   Get a New Private Key
*   Delegate Domain-wide Authority to Your Service Account
*   Get an Immutable Google Apps ID

### Get a New Private Key

1.  Access your [Google Service Account](https://console.developers.google.com/projectselector/iam-admin/serviceaccounts%C2%A0).
2.  In the IAM & admin section select **Service accounts**.
3.  If you need to create a new project, click **CREATE** do the following:
    1.  In the **New Project** window, type a project name, select an organization from the drop-down list  and then select a location. 
    2.  Click **CREATE**.
4.  In the Service accounts section, click **Create Service Account**.
5.  In the **Create service account** window, type a name for the service account, add a description and then click **CREATE**.
6.  Click **Continue.**
7.  In the **Create key** section, click **CREATE KEY**.
8.  Select Key type **JSON** and click **CREATE**.
9.  Click **DONE**.<br/>A key pair is generated and automatically downloads.
10.  In the **Actions** column, select the service and then click **edit**.
    ![mceclip1.png](https://github.com/demisto/content/raw/6d9ac954729a6dffd6be51b658e7987824238462/Integrations/Gmail/doc_imgs/gmail-enable.png) 
11.  Under the show domain wide delegation, select **Enable G Suite Domain-wide Delegation**.
    ![gmail-_enable.png](https://github.com/demisto/content/raw/6d9ac954729a6dffd6be51b658e7987824238462/Integrations/Gmail/doc_imgs/gmail-enable.png)  
    NOTE: Copy the value of the Unique ID for the client name in step 2 in Delegate Domain-wide Authority to Your Service Account. 
12.  Click Save.
13.  In the top search bar, search for _admin sdk_.
14.  Click **Enable**.

### Delegate Domain-wide Authority to Your Service Account

* * *

1.  Access the [Google Administrator Console](http://admin.google.com/).
2.  Enter a client name (the Unique ID) and paste the following into the One or More API Scopes textbox. 
    
``` https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.device.mobile.action,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/gmail.settings.sharing,https://www.googleapis.com/auth/gmail.send,https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/admin.directory.device.chromeos,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.rolemanagement,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/gmail.readonly,https://mail.google.com,https://www.googleapis.com/auth/gmail.compose ```
    
![](https://github.com/demisto/content/raw/6d9ac954729a6dffd6be51b658e7987824238462/Integrations/Gmail/doc_imgs/mceclip1.png)
    

### Get an Immutable Google Apps ID Parameters

* * *

In order to revoke/fetch a user role, you need an Immutable Google Apps ID param.

1.  Open [https://admin.google.com](https://admin.google.com/) (as in step 2).
2.  Navigate to **Security** > **Set up single sign-on (SSO)**.   
    The SSO URL is the Immutable Google Apps ID.
3.  Record the SSO URL, which is the Immutable Google Apps ID, and copy it for later use.  
    
    ![](https://github.com/demisto/content/raw/6d9ac954729a6dffd6be51b658e7987824238462/Integrations/Gmail/doc_imgs/mceclip2.png)
    

Configure the Gmail Integration on Cortex XSOAR
------------------------------------------

1.  Navigate to **Settings** > **Integrations** > **Servers & Services**.
2.  Search for Gmail.
3.  Click **Add instance** to create and configure a new integration instance.  
    -   **Name**: a textual name for the integration instance.
    -   **Email of user with admin capabilities** - Enter the email address of the user that you set admin capabilities for.
    -   **Password (JSON):**  Paste the Service account JSON you generated in the Google console, which includes the JSON key. The JSON might be long, so you can expand the text box.
    -   **Immutable Google Apps ID:** Only the Cxxxxxxxx, section is needed.
    -   **Events query** - Use this to filter out the fetched messages.  
        The query language follows the Gmail query specification example: "from:someuser@example.com rfc822msgid:<somemsgid@example.com> is:unread". For more information, read the [Gmail Query Language documentation](https://support.google.com/mail/answer/7190?hl=en).
    -   **Events user key**\- Use this to specify the email account to search for messages. By default, the integration uses the email address specified in the admin instance. 
        ![](https://github.com/demisto/content/raw/6d9ac954729a6dffd6be51b658e7987824238462/Integrations/Gmail/doc_imgs/mceclip0.png)
        
    *   **Incident type**
    *   **Demisto engine**
4.  Click **Test** to validate the URLs and connection.

Use Cases
---------

1.  Monitors a mailbox by using the integration fetch incident capability to monitor a mailbox and create incidents for new filtered emails.
2.  Searches a mailbox for emails with PDF attachments by using the following command.  
    `gmail-search user-id=admin@demisto.com filename=”pdf” after=”2018/05/10”.`
3.  Deletes emails by using the following command.  
    `!gmail-delete-mail user-id=admin@demisto.com message-id=164d2110e0152660`

Fetched Incidents Data
----------------------

1.  Incident Name
2.  Occurred
3.  Owner
4.  Type
5.  Severity
6.  Email From
7.  Email Message ID
8.  Email Subject
9.  Email To
10.  Attachment Extension
11.  Attachment Name
12.  Email Body
13.  Email Body Format

Commands
--------

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1.  Delete a user: gmail-delete-user
2.  Get tokens for a user: gmail-get-tokens-for-user
3.  Get information for a Google user: gmail-get-user
4.  Get all available Google roles: gmail-get-user-roles
5.  Get Gmail message attachments: gmail-get-attachments
6.  Get a Gmail message: gmail-get-mail
7.  Search a user's Gmail records: gmail-search
8.  Search in all Gmail mailboxes: gmail-search-all-mailboxes
9.  List all Google users: gmail-list-users
10.  Revoke a Google user's role: gmail-revoke-user-role
11.  Create a new user: gmail-create-user
12.  Delete mail from a mailbox: gmail-delete-mail
13.  Get message in an email thread: gmail-get-thread
14.  Move mail to a different folder: gmail-move-mail
15.  Move a mail to a different mailbox: gmail-move-mail-to-mailbox
16.  Add a rule to delete an email: gmail-add-delete-filter
17.  Add a new filter: gmail-add-filter
18.  Get a list of filters in a mailbox: gmail-list-fillter
19.  Remove a filter from a mail: gmail-remove-filter
20.  Move a mail to a different mailbox: gmail-move-mail-to-mailbox
21.  Hide a user's information: gmail-hide-user-in-directory
22.  Set a password: gmail-set-password
23.  Get an auto reply message for the user: gmail-get-autoreply
24.  Set an auto-reply for the user: gmail-set-autoreply
25.  Add a delete user to a mailbox: gmail-delegate-user-mailbox
26.  Send an email using Gmail: send-mail
27.  Reply an email using Gmail: reply-mail
28.  Removers a delegate from a mailbox: gmail-remove-delegated-mailbox
29.  Get details of a specific role: gmail-get-role

### 1. Delete a user

* * * * *

Deletes a Gmail user.

##### Base Command

`gmail-delete-user`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The "me" special value can be used to indicate the authenticated user.|Required|


##### Command Example

      !gmail-delete-user user-id=user@demistodev.com

##### Human Readable Output

User user@demistodev.com have been deleted.

### 2. Get tokens for a Google user

* * * * *

Lists all tokens associated with a specified user applications.

##### Base Command

`gmail-get-tokens-for-user`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The "me" special value can be used to indicate the authenticated user.|Required|


##### Command Example

    !gmail-get-tokens-for-user user-id=admin@demistodev.com

##### Context Example

    {
        "Tokens": [
            {
                "ClientId": "292824132082.apps.googleusercontent.com",
                "DisplayText": "Google APIs Explorer",
                "Kind": "admin#directory#token",
                "Scopes": [
                    "https://www.googleapis.com/auth/ediscovery.readonly",
                    "openid",
                    "https://www.googleapis.com/auth/ediscovery",
                    "https://www.googleapis.com/auth/cloudkms",
                    "https://www.googleapis.com/auth/admin.directory.user.security",
                    "https://www.googleapis.com/auth/admin.directory.user",
                    "https://www.googleapis.com/auth/admin.directory.user.readonly",
                    "https://www.googleapis.com/auth/admin.directory.rolemanagement",
                    "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly"
                ],
                "UserKey": "103020731686044834269"
            },
            {
                "ClientId": "422358954086-4fvv287aojmge1qaqe9m5mmgmbuhg1hj.apps.googleusercontent.com",
                "DisplayText": "Go Phish!",
                "Kind": "admin#directory#token",
                "Scopes": [
                    "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
                    "https://www.googleapis.com/auth/script.send_mail",
                    "https://www.googleapis.com/auth/userinfo.email",
                    "openid",
                    "https://www.googleapis.com/auth/script.storage",
                    "https://www.googleapis.com/auth/gmail.addons.execute",
                    "https://www.googleapis.com/auth/admin.directory.user.readonly"
                ],
                "UserKey": "103020731686044834269"
            },
            {
                "ClientId": "950822307886-oiv25bpm32dtp21eabn2k5lf1ba7koum.apps.googleusercontent.com",
                "DisplayText": "Demisto KMS DEV",
                "Kind": "admin#directory#token",
                "Scopes": [
                    "https://www.googleapis.com/auth/cloud-platform"
                ],
                "UserKey": "103020731686044834269"
            },
            {
                "ClientId": "371237729773-oj8m98u7esgqep8snt9aold136opo3fi.apps.googleusercontent.com",
                "DisplayText": "Google Data Studio",
                "Kind": "admin#directory#token",
                "Scopes": [
                    "https://www.googleapis.com/auth/bigquery.readonly"
                ],
                "UserKey": "103020731686044834269"
            },
            {
                "ClientId": "805864674475-3abs2rivkn7kreou30b8ru8esnti4oih.apps.googleusercontent.com",
                "DisplayText": "Postman",
                "Kind": "admin#directory#token",
                "Scopes": [
                    "https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/userinfo.email"
                ],
                "UserKey": "103020731686044834269"
            },
            {
                "ClientId": "77185425430.apps.googleusercontent.com",
                "DisplayText": "Google Chrome",
                "Kind": "admin#directory#token",
                "Scopes": [
                    "https://www.google.com/accounts/OAuthLogin"
                ],
                "UserKey": "103020731686044834269"
            },
            {
                "ClientId": "1041831412594-vrl2ne8nr3rnireuc39qk4i7aqgu0n39.apps.googleusercontent.com",
                "DisplayText": "demisto",
                "Kind": "admin#directory#token",
                "Scopes": [
                    "https://www.googleapis.com/auth/admin.directory.group.readonly",
                    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
                    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                    "https://www.googleapis.com/auth/drive.readonly",
                    "https://www.googleapis.com/auth/calendar.readonly",
                    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
                    "https://www.googleapis.com/auth/admin.directory.user.readonly",
                    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
                    "https://www.googleapis.com/auth/tasks"
                ],
                "UserKey": "103020731686044834269"
            },
            {
                "ClientId": "800521135851-nh4gf3m9kbpu83h2sl8sm8a21e7g7ldi.apps.googleusercontent.com",
                "DisplayText": "BetterCloud",
                "Kind": "admin#directory#token",
                "Scopes": [
                    "https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/userinfo.email",
                    "openid",
                    "https://www.googleapis.com/auth/admin.directory.user.readonly"
                ],
                "UserKey": "103020731686044834269"
            }
        ]
    }

##### Human Readable Output

### **Tokens**:

|**DisplayText**|**ClientId**|**Kind**|**Scopes**|**UserKey**|
|:--------------|:-----------|:-------|:---------|:----------|
|Google APIs Explorer|292824132082.apps.googleusercontent.com|admin#directory#token|https://www.googleapis.com/auth/ediscovery.readonly, <br/> openid, <br/> https://www.googleapis.com/auth/ediscovery, <br/> https://www.googleapis.com/auth/cloudkms, <br/> https://www.googleapis.com/auth/admin.directory.user.security, <br/> https://www.googleapis.com/auth/admin.directory.user, <br/> https://www.googleapis.com/auth/admin.directory.user.readonly, <br/> https://www.googleapis.com/auth/admin.directory.rolemanagement, <br/> https://www.googleapis.com/auth/cloud-platform, <br/> https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly|103020731686044834269|
|Go Phish!|422358954086-4fvv287aojmge1qaqe9m5mmgmbuhg1hj.apps.googleusercontent.com|admin#directory#token|https://www.googleapis.com/auth/gmail.addons.current.message.readonly, <br/> https://www.googleapis.com/auth/script.send_mail, <br/> https://www.googleapis.com/auth/userinfo.email, <br/> openid, <br/> https://www.googleapis.com/auth/script.storage, <br/> https://www.googleapis.com/auth/gmail.addons.execute, <br/> https://www.googleapis.com/auth/admin.directory.user.readonly|103020731686044834269|
|Demisto KMS DEV|950822307886-oiv25bpm32dtp21eabn2k5lf1ba7koum.apps.googleusercontent.com|admin#directory#token|https://www.googleapis.com/auth/cloud-platform|103020731686044834269|
|Google Data Studio|371237729773-oj8m98u7esgqep8snt9aold136opo3fi.apps.googleusercontent.com|admin#directory#token|https://www.googleapis.com/auth/bigquery.readonly|103020731686044834269|
|Postman|805864674475-3abs2rivkn7kreou30b8ru8esnti4oih.apps.googleusercontent.com|admin#directory#token|https://www.googleapis.com/auth/userinfo.profile, <br/> https://www.googleapis.com/auth/userinfo.email|103020731686044834269|
|Google Chrome|77185425430.apps.googleusercontent.com|admin\#directory\#token|https://www.google.com/accounts/OAuthLogin|103020731686044834269|
|demisto|1041831412594-vrl2ne8nr3rnireuc39qk4i7aqgu0n39.apps.googleusercontent.com|admin\#directory#token|https://www.googleapis.com/auth/admin.directory.group.readonly, <br/> https://www.googleapis.com/auth/admin.directory.orgunit.readonly, <br/> https://www.googleapis.com/auth/admin.reports.audit.readonly, <br/> https://www.googleapis.com/auth/drive.readonly, <br/> https://www.googleapis.com/auth/calendar.readonly, <br/> https://www.googleapis.com/auth/admin.directory.device.mobile.readonly, <br/> https://www.googleapis.com/auth/admin.directory.user.readonly, <br/> https://www.googleapis.com/auth/admin.reports.usage.readonly, <br/> https://www.googleapis.com/auth/tasks|103020731686044834269|
|BetterCloud|800521135851-nh4gf3m9kbpu83h2sl8sm8a21e7g7ldi.apps.googleusercontent.com|admin\#directory\#token|https://www.googleapis.com/auth/userinfo.profile, <br/> https://www.googleapis.com/auth/userinfo.email, <br/> openid, <br/> https://www.googleapis.com/auth/admin.directory.user.readonly|103020731686044834269|


### 3. Get information for a Google user

* * * * *

Retrieves information for a specified Google user.

##### Base Command

`gmail-get-user`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The "me" special value can be used to indicate the authenticated user.|Required|
|projection|The subset of fields to fetch for the user. Can be: "basic": Do not include any custom fields for the user (default), "custom": Includes custom fields from schema requested in custom-field-mask, "full": Includes all fields associated with the user.|Optional|
|view-type-public-domain|Whether to fetch the administrator or public view of the user. Can be admin\_view (default), which includes both administrator and domain-public fields; or "domain\_public", which includes user fields that are publicly visible to other users in the domain.|Optional|
|custom-field-mask|A comma separated list of schema names. All fields from these schemas are fetched. This should only be set when projection=custom.|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Account.Type|String|The account type. For example, "AD", "LocalOS", "Google", "AppleID", and so on.|
|Account.ID|String|The unique ID for the account (integration specific). For AD accounts this is the Distinguished Name (DN).|
|Account.DisplayName|string|The display name.|
|Account.Gmail.Address|string|Email assigned with the current account.|
|Account.Email.Address|String|The email address of the account.|
|Account.Groups|String|Groups to which the account belongs (integration specific). For example, for AD, these are the groups in which the account is a member.|
|Account.Domain|String|The domain of the account.|
|Account.Username|String|The account username in the relevant system.|
|Account.OrganizationUnit|String|The Organization Unit (OU) of the account.|


##### Command Example

      !gmail-get-user user-id=user@demistodev.com

##### Context Example

    {
        "Account": [
            {
                "CustomerId": "C02f0zfqw",
                "DisplayName": "John Snow",
                "Domain": "demistodev.com",
                "Email": {
                    "Address": "user@demistodev.com"
                },
                "Gmail": {
                    "Address": "user@demistodev.com"
                },
                "Group": "admin#directory#user",
                "Groups": "admin#directory#user",
                "ID": "117047108909890245378",
                "Type": "Google",
                "UserName": "John",
                "Username": "John",
                "VisibleInDirectory": true
            }
        ]
    }

##### Human Readable Output

##### User user@demistodev.com:

|**Type**|**ID**|**Username**|**DisplayName**|**Groups**|**CustomerId**|**Domain**|**Email**|**VisibleInDirectory**|
|:-------|:-----|:-----------|:--------------|:---------|:-------------|:---------|:--------|:---------------------|
|Google|117047108909890245378|John|John Snow|admin\#directory\#user|C02f0zfqw|demistodev.com|Address: user@demistodev.com|true|


### 4. Get all available Google roles

* * * * *

Lists all available Google roles for a specified Google user.

##### Base Command

`gmail-get-user-roles`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The "me" special value can be used to indicate the authenticated user.|Required|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|GoogleApps.Role.RoleAssignmentId|string|The unique ID of the role assignment.|
|GoogleApps.Role.ScopeType|string|The scope type of the role.|
|GoogleApps.Role.Kind|string|The kind of the Role.|
|GoogleApps.Role.OrgUnitId|string|Organization in which user was assigned.|
|GoogleApps.Role.ID|string|The inner role ID.|
|GoogleApps.Role.AssignedTo|string|User ID who was assigned to the role.|


##### Command Example

      !gmail-get-user-roles user-id=admin@demistodev.com

##### Context Example

    {
        "Gmail.Role": [
            {
                "AssignedTo": "103020731686044834269",
                "ID": "10740456929361921",
                "Kind": "admin#directory#roleAssignment",
                "OrgUnitId": "",
                "RoleAssignmentId": "10740456929361921",
                "ScopeType": "CUSTOMER"
            }
        ]
    }

##### Human Readable Output

### User Roles of admin@demistodev.com:

|**ID**|**AssignedTo**|**RoleAssignmentId**|**ScopeType**|**Kind**|
|:-----|:-------------|:-------------------|:------------|:-------|
|10740456929361921|103020731686044834269|10740456929361921|CUSTOMER|admin\#directory\#roleAssignment|


### 5. Get Gmail message attachments

* * * * *

Retrieves Gmail attachments sent to a specified Google user.

##### Base Command

`gmail-get-attachments`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|message-id|The ID of the message to retrieve.|Required|
|user-id|The user's email address. The "me" special value can be used to indicate the authenticated user.|Required|



##### Command Example

      !gmail-get-attachments message-id=16d4316a25a332e4 user-id=admin@demistodev.com

### 6. Get a Gmail message

* * * * *

Retrieves a Gmail message sent to a specified Google user.

##### Base Command

`gmail-get-mail`

##### Required Permissions

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The special value me can be used to indicate the authenticated user.|Required|
|message-id|The ID of the message to retrieve.|Required|
|format|The format in which to return the message. Can be: "full": Returns the full email message data with body content parsed in the payload field; the raw field is not used. (default) / "metadata": Returns only the email message ID, labels, and email headers / "minimal": Returns only the email message ID and labels; does not return the email headers, body, or payload / "raw": Returns the full email message data with body content in the raw field as a base64url encoded string; the payload field is not used.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Gmail.ID|String|Inner ID of the Gmail message.|
|Gmail.ThreadId|string|The thread ID.|
|Gmail.Format|string|MIME type of email.|
|Gmail.Labels|string|Labels of the specific email.|
|Gmail.To|String|Email Address of the receiver.|
|Gmail.From|String|Email Address of the sender.|
|Gmail.Cc|string|Additional recipient email address (CC).|
|Email.Bcc|string|Additional recipient email address (BCC).|
|Gmail.Subject|string|Subject of the email.|
|Gmail.Body|string|The content of the email.|
|Gmail.Attachments|unknown|The attachments of the email. Attachments ID's are separated by ','.|
|Gmail.Headers|unknown|All headers of the specific email (list).|
|Email.Mailbox|string|The email mailbox.|
|Email.To|String|The recipient of the email.|
|Email.From|String|The sender of the email.|
|Email.CC|String|Additional recipient email address (CC).|
|Email.BCC|String|Additional recipient email address (BCC).|
|Email.Format|String|The format of the email.|
|Email.Body/HTML|String|The HTML version of the email.|
|Email.Body/Text|String|The plain-text version of the email.|
|Email.Subject|String|The subject of the email.|
|Email.Headers|String|The headers of the email.|
|Email.Attachments.entryID|Unknown|Attachments ids separated by ','.|
|Email.Date|String|The date the email was received.|


##### Command Example

      !gmail-get-mail user-id=admin@demistodev.com message-id=16d4316a25a332e4

##### Context Example

    {
        "Email": [
            {
                "Attachment Names": "puppy.png",
                "Attachments": [
                    {
                        "ID": "",
                        "Name": "puppy.png"
                    }
                ],
                "BCC": "",
                "Body/HTML": "",
                "Body/Text": "",
                "CC": "",
                "Date": "Tue, 17 Sep 2019 23:36:59 -0700",
                "Format": "multipart/mixed",
                "From": "admin@demistodev.com",
                "Headers": [
                    {
                        "Name": "Received",
                        "Value": "from 1041831412594 named unknown by gmailapi.google.com with HTTPREST; Tue, 17 Sep 2019 23:36:59 -0700"
                    },
                    {
                        "Name": "Content-Type",
                        "Value": "multipart/mixed; boundary=\"===============3751607758919896682==\""
                    },
                    {
                        "Name": "MIME-Version",
                        "Value": "1.0"
                    },
                    {
                        "Name": "to",
                        "Value": "admin@demistodev.com"
                    },
                    {
                        "Name": "cc",
                        "Value": ""
                    },
                    {
                        "Name": "bcc",
                        "Value": ""
                    },
                    {
                        "Name": "from",
                        "Value": "admin@demistodev.com"
                    },
                    {
                        "Name": "subject",
                        "Value": "attachment"
                    },
                    {
                        "Name": "reply-to",
                        "Value": ""
                    },
                    {
                        "Name": "Date",
                        "Value": "Tue, 17 Sep 2019 23:36:59 -0700"
                    },
                    {
                        "Name": "Message-Id",
                        "Value": "<>"
                    }
                ],
                "ID": "16d4316a25a332e4",
                "RawData": null,
                "Subject": "attachment",
                "To": "admin@demistodev.com"
            }
        ],
        "Gmail": [
            {
                "Attachment Names": "puppy.png",
                "Attachments": [
                    {
                        "ID": "",
                        "Name": "puppy.png"
                    }
                ],
                "Bcc": "",
                "Body": "",
                "Cc": "",
                "Date": "Tue, 17 Sep 2019 23:36:59 -0700",
                "Format": "multipart/mixed",
                "From": "admin@demistodev.com",
                "Headers": [
                    {
                        "Name": "Received",
                        "Value": "from 1041831412594 named unknown by gmailapi.google.com with HTTPREST; Tue, 17 Sep 2019 23:36:59 -0700"
                    },
                    {
                        "Name": "Content-Type",
                        "Value": "multipart/mixed; boundary=\"===============3751607758919896682==\""
                    },
                    {
                        "Name": "MIME-Version",
                        "Value": "1.0"
                    },
                    {
                        "Name": "to",
                        "Value": "admin@demistodev.com"
                    },
                    {
                        "Name": "cc",
                        "Value": ""
                    },
                    {
                        "Name": "bcc",
                        "Value": ""
                    },
                    {
                        "Name": "from",
                        "Value": "admin@demistodev.com"
                    },
                    {
                        "Name": "subject",
                        "Value": "attachment"
                    },
                    {
                        "Name": "reply-to",
                        "Value": ""
                    },
                    {
                        "Name": "Date",
                        "Value": "Tue, 17 Sep 2019 23:36:59 -0700"
                    },
                    {
                        "Name": "Message-Id",
                        "Value": "<>"
                    }
                ],
                "Html": "",
                "ID": "16d4316a25a332e4",
                "Labels": "UNREAD, SENT, INBOX",
                "Mailbox": "admin@demistodev.com",
                "RawData": null,
                "Subject": "attachment",
                "ThreadId": "16d4316a25a332e4",
                "To": "admin@demistodev.com",
                "Type": "Gmail"
            }
        ]
    }

##### Human Readable Output

### Email:

|**Mailbox**|**ID**|**Subject**|**From**|**To**|**Labels**|**Attachment Names**|**Format**|
|:----------|:-----|:----------|:-------|:-----|:---------|:-------------------|:---------|
|admin@demistodev.com|16d4316a25a332e4|attachment|admin@demistodev.com|admin@demistodev.com|UNREAD, SENT, INBOX|puppy.png|multipart/mixed|

### 7. Search a user's Gmail records

* * * * *

Searches for Gmail records of a specified Google user.

##### Base Command

`gmail-search`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The "me" special value can be used to indicate the authenticated user.|Required|
|query|Returns messages matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com rfc822msgid: is:unread". For more syntax information see "https://support.google.com/mail/answer/7190?hl=en"|Optional|
|max-results|Maximum number of results to return. Default is 100. Maximum is 500. Can be 1 to 500, inclusive.|Optional|
|fields|Enables partial responses to be retrieved, separated by commas. For more information, see https://developers.google.com/gdata/docs/2.0/basics#PartialResponse.|Optional|
|labels-ids|Only returns messages with labels that match all of the specified label IDs in a comma separated list.|Optional|
|page-token|Page token to retrieve a specific page of results in the list.|Optional|
|include-spam-trash|Include messages from SPAM and TRASH in the results. (Default: false)|Optional|
|from|Specify the sender. For example, "john"|Optional|
|to|Specify the receiver. For example, "john"|Optional|
|subject|Words in the subject line. For example, "alert"|Optional|
|filename|Attachments with a certain name or file type. For example, "pdf" or "report.pdf"|Optional|
|in|Messages in any folder, including Spam and Trash. For example: shopping|Optional|
|after|Search for messages sent after a certain time period. For example: 2018/05/06|Optional|
|before|Search for messages sent before a certain time period. for example: 2018/05/09|Optional|
|has-attachments|Whether to search for messages sent with attachments (boolean value).|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Gmail.ID|string|Inner ID of the Gmail message.|
|Gmail.ThreadId|string|The thread ID.|
|Gmail.Format|string|MIME type of email.|
|Gmail.Labels|string|Labels of the specific email.|
|Gmail.To|string|Email Address of the receiver.|
|Gmail.From|string|Email Address of the sender.|
|Gmail.Cc|string|Additional recipient email address (CC).|
|Gmail.Bcc|string|Additional recipient email address (BCC).|
|Gmail.Subject|string|Subject of the specific email.|
|Gmail.Body|string|The content of the email.|
|Gmail.Attachments|unknown|Attachment details. Attachments IDs are separated by ','.|
|Gmail.Headers|unknown|All headers of a specific email (list).|
|Gmail.Mailbox|string|The email mailbox.|
|Email.To|String|The recipient of the email.|
|Email.From|String|The sender of the email.|
|Email.CC|String|Additional recipient email address (CC).|
|Email.BCC|String|Additional recipient email address (BCC).|
|Email.Format|String|The format of the email.|
|Email.Body/HTML|String|The HTML version of the email.|
|Email.Body/Text|String|The plain-text version of the email.|
|Email.Subject|String|The subject of the email.|
|Email.Headers|String|The headers of the email.|
|Email.Attachments.entryID|Unknown|Email Attachment IDs. Separated by ','.|
|Email.Date|String|The date the email was received.|

##### Command Example

      !gmail-search user-id=yarden@demistodev.com after=2019/03/20 before=2019/04/01 query=playbook max-results=2

##### Context Example

    {
        “Gmail”: {
        "Email": [
            {
                "ID": ,
                "ThreadId": ,
                "Format": "multipart/mixed",
                "Labels": "UNREAD, CATEGORY_PERSONAL, INBOX",
                "To": "example@demisto.com",
                "From": "example@demisto.com",
                "Cc": ,
                "Bcc": ,
                "Subject": “email subject”,
                "Body": "email body",
                "Headers" : [
            {
                       "Name": ,
                       "Value": ,
                   },
                   {
                       "Name": ,
                       "Value": ,
                   }
                ],
                "Attachments": [
                    {
                        "Name": ,
                        "ID": ,
                    }
                ],
                "Type": "Gmail",
            }
          ]
        }
    }
     

##### Human Readable Output

##### Search in yarden@demistodev.com:

query: "after:2019/03/20 before:2019/04/01 playbook"

|**Mailbox**|**ID**|**Subject**|**From**|**To**|**Labels**|**Attachment Names**|**Format**|**Body**|
|:----------|:-----|:----------|:-------|:-----|:---------|:-------------------|:---------|:-------|
|yarden@demistodev.com|169d1994d578242b|special test via playbook (2)|Avishai Brandeis \<avishai@demistodev.onmicrosoft.com\>|"yarden@demistodev.com" \<yarden@demistodev.com\>|UNREAD, IMPORTANT, CATEGORY\_PERSONAL, INBOX|attach.txt, test.txt, test2.txt|multipart/mixed|this is a test by playbook|
|yarden@demistodev.com|169d199021c5df09|special test via playbook (1)|Avishai Brandeis \<avishai@demistodev.onmicrosoft.com\>|"yarden@demistodev.com" \<yarden@demistodev.com\>|UNREAD, IMPORTANT, CATEGORY\_PERSONAL, INBOX|test.txt|multipart/mixed|this is a test by playbook|


### 8. Search in all Gmail mailboxes

* * * * *

Searches the Gmail records for all Google users.

##### Base Command

`gmail-search-all-mailboxes`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|query|Returns messages matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com rfc822msgid: is:unread". For more syntax information,see "https://support.google.com/mail/answer/7190?hl=en"|Optional|
|max-results|Maximum number of results to return. Default is 100. Maximum is 500. Acceptable values are 1 to 500, inclusive.|Optional|
|fields|Enables partial responses to be retrieved in a comma separated list. For more information, see https://developers.google.com/gdata/docs/2.0/basics#PartialResponse.|Optional|
|labels-ids|Only returns messages with labels that match all of the specified label IDs in a comma separated list.|Optional|
|page-token|Page token to retrieve a specific page of results in the list.|Optional|
|include-spam-trash|Includes messages from SPAM and TRASH in the results. (Default: false)|Optional|
|from|Specifies the sender. For example, "john"|Optional|
|to|Specifies the receiver. For example, "john"|Optional|
|subject|Words in the subject line. For example, "alert"|Optional|
|filename|Attachments with a certain name or file type. For example, "pdf" or "report.pdf"|Optional|
|in|Messages in any folder, including Spam and Trash. For example, shopping|Optional|
|after|Search for messages sent after a certain time period. For example, 2018/05/06|Optional|
|before|Search for messages sent before a certain time period. For example, 2018/05/09|Optional|
|has-attachments|Whether to search for messages sent with attachments.|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Gmail.ID|string|Inner ID of the Gmail message.|
|Gmail.ThreadId|string|The thread ID.|
|Gmail.Format|string|MIME type of the email.|
|Gmail.Labels|string|Labels of a specific email.|
|Gmail.To|string|Email Address of the receiver.|
|Gmail.From|string|Email Address of the sender.|
|Gmail.Cc|string|Additional recipient email address (CC).|
|Gmail.Bcc|string|Additional recipient email address (BCC).|
|Gmail.Subject|string|Subject of the specific email.|
|Gmail.Body|string|The content of the email.|
|Gmail.Attachments|unknown|The attachments of the email. IDs are separated by ','.|
|Gmail.Headers|unknown|All headers of specific mail (list).|
|Gmail.Mailbox|string|The Gmail Mailbox.|
|Email.To|String|The recipient of the email.|
|Email.From|String|The sender of the email.|
|Email.CC|String|Additional recipient email address (CC).|
|Email.BCC|String|Additional recipient email address (BCC).|
|Email.Format|String|The format of the email.|
|Email.Body/HTML|String|The HTML version of the email.|
|Email.Body/Text|String|The plain-text version of the email.|
|Email.Subject|String|The subject of the email.|
|Email.Headers|String|The headers of the email.|
|Email.Attachments.entryID|Unknown|Email Attachments. IDs are separated by ','.|
|Email.Date|String|The date the email was received.|


##### Command Example

    !gmail-search-all-mailboxes after=2019/04/10 max-results=3 before=2019/04/15 query=test

##### Context Example

        “Gmail”: {
        "Email": [
            {
                "ID": ,
                "ThreadId": ,
                "Format": "multipart/mixed",
                "Labels": "UNREAD, CATEGORY_PERSONAL, INBOX",
                "To": "example@demisto.com",
                "From": "example@demisto.com",
                "Cc": ,
                "Bcc": ,
                "Subject": “email subject”,
                "Body": "email body",
                "Headers" : [
            {
                       "Name": ,
                       "Value": ,
                   },
                   {
                       "Name": ,
                       "Value": ,
                   }
                ],
                "Attachments": [
                    {
                        "Name": ,
                        "ID": ,
                    }
                ],
                "Type": "Gmail",
            }
          ]
        }
    }

##### Human Readable Output

##### Search in admin@demistodev.com:

query: "after:2019/04/10 before:2019/04/15 test" \*\*No entries.\*\*

### Search in art@demistodev.com:

query: "after:2019/04/10 before:2019/04/15 test" \*\*No entries.\*\*

|**Mailbox**|**ID**|**Subject**|**From**|**To**|**Labels**|**Attachment Names**|**Format**|**Body**|
|:----------|:-----|:----------|:-------|:-----|:---------|:-------------------|:---------|:-------|
|yarden@demistodev.com|16a1d1886b5abaeb|special test via playbook (2)|Avishai Brandeis \<avishai@demistodev.onmicrosoft.com\>|"yarden@demistodev.com" \<yarden@demistodev.com\>|UNREAD, CATEGORY\_PERSONAL, INBOX|attach.txt, test.txt, test2.txt|multipart/mixed|this is a test by playbook|
|yarden@demistodev.com|16a1d182a271708c|special test via playbook (1)|Avishai Brandeis \<avishai@demistodev.onmicrosoft.com\>|"yarden@demistodev.com" \<yarden@demistodev.com\>|UNREAD, IMPORTANT, CATEGORY\_PERSONAL, INBOX|test.txt|multipart/mixed|this is a test by playbook|
|yarden@demistodev.com|16a1d0bd1701cd1a|special test via playbook (2)|Avishai Brandeis \<avishai@demistodev.onmicrosoft.com\>|"yarden@demistodev.com" \<yarden@demistodev.com\>|UNREAD, CATEGORY\_PERSONAL, INBOX|attach.txt, test.txt, test2.txt|multipart/mixed|this is a test by playbook|


### 9. List all Google users

* * * * *

Lists all Google users in a domain.

##### Base Command

`gmail-list-users`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|projection|The subset of fields to fetch for the user. Can be "basic": Do not include any custom fields for the user. (default), "custom": Include custom fields from schemas requested in customFieldMask, "full": Include all fields associated with this user.|Optional|
|domain|The domain name. Use this field to get fields from only one domain. To return all domains for a customer account, use the customer query parameter.|Optional|
|customer|The unique ID for the customers Google account. Default is the value specified in the integration configuration. For a multi-domain account, to fetch all groups for a customer, use this field instead of domain.|Optional|
|event|The event on which subscription intended (if subscribing). Can be "add", "delete", "makeAdmin", "undelete", or "update".|Optional|
|max-results|Maximum number of results to return. Default is 100. Maximum is 500. Can be 1 to 500, inclusive.|Optional|
|custom-field-mask|A comma-separated list of schema names. All fields from these schemas are fetched. Must be set when projection=custom.|Optional|
|query|Query string search. Should be of the form "". Complete documentation is at https://developers.google.com/admin-sdk/directory/v1/guides/search-users|Optional|
|show-deleted|If true, retrieves the list of deleted users. Default is false.|Optional|
|sort-order|How to sort out results. Can be ASCENDING/DESCENDING|Optional|
|token|Token to authorize and authenticate the action.|Optional|
|view-type-public-domain|Whether to fetch either the administrator or public view of the user. Can be admin\_view (default), which includes both administrator and domain-public fields or "domain\_public"(includes fields for the user that are publicly visible to other users in the domain).|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Account.Type|String|The account type. For example, "AD", "LocalOS", "Google", "AppleID", and so on.|
|Account.ID|String|The unique ID for the account (integration specific). For AD accounts this is the Distinguished Name (DN).|
|Account.DisplayName|String|The display name.|
|Account.Gmail.Address|string|Email assigned with the current account.|
|Account.Email.Adderss|String|The email address of the account.|
|Account.Groups|String|Groups to which the account belongs (integration specific). For example, for AD these are the groups in which the account is member.|
|Account.Domain|String|The domain of the account.|
|Account.Username|String|The username of the account.|
|Account.OrganizationUnit|String|The Organization Unit (OU) of the account.|


##### Command Example

      !gmail-list-users query=John show-deleted=False

##### Context Example

    {
        "Account": [
            {
                "CustomerId": "C02f0zfqw",
                "DisplayName": "John Smith",
                "Domain": "demistodev.com",
                "Email": {
                    "Address": "johns@demistodev.com"
                },
                "Gmail": {
                    "Address": "johns@demistodev.com"
                },
                "Group": "admin#directory#user",
                "Groups": "admin#directory#user",
                "ID": "105877121188199653770",
                "Type": "Google",
                "UserName": "John",
                "Username": "John",
                "VisibleInDirectory": true
            },
            {
                "CustomerId": "C02f0zfqw",
                "DisplayName": "John Snow",
                "Domain": "demistodev.com",
                "Email": {
                    "Address": "user@demistodev.com"
                },
                "Gmail": {
                    "Address": "user@demistodev.com"
                },
                "Group": "admin#directory#user",
                "Groups": "admin#directory#user",
                "ID": "117047108909890245378",
                "Type": "Google",
                "UserName": "John",
                "Username": "John",
                "VisibleInDirectory": true
            }
        ]
    }

##### Human Readable Output

### Users:

|**Type**|**ID**|**Username**|**DisplayName**|**Groups**|**CustomerId**|**Domain**|**Email**|**VisibleInDirectory**|
|:-------|:-----|:-----------|:--------------|:---------|:-------------|:---------|:--------|:---------------------|
|Google|105877121188199653770|John|John Smith|admin#directory#user|C02f0zfqw|demistodev.com|Address: johns@demistodev.com|true|
|Google|117047108909890245378|John|John Snow|admin#directory#user|C02f0zfqw|demistodev.com|Address: user@demistodev.com|true|

### 10. Revoke a Google user's role

* * * * *

Revokes a role for a specified Google user.

##### Base Command

`gmail-revoke-user-role`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The special value me can be used to indicate the authenticated user.|Optional|
|role-assignment-id|The immutable ID of the role assignment.|Required|

### 11. Create a new user

* * * * *

Creates a new Gmail user.

##### Base Command

`gmail-create-user`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|email|The user's primary email address. The primary email address must be unique and cannot be an alias of another user.|Required|
|first-name|The user's first name.|Required|
|family-name|The user's last name.|Required|
|password|Stores the password for the user account. A password can contain any combination of ASCII characters. A minimum of 8 characters is required. The maximum length is 100 characters.|Required|

 

##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Account.Type|String|The account type. For example, "AD", "LocalOS", "Google", "AppleID", and so on.|
|Account.ID|String|The unique ID for the account (integration specific). For AD accounts this is the Distinguished Name (DN).|
|Account.DisplayName|string|The display name.|
|Account.Gmail.Address|string|Email assigned with the current account.|
|Account.Email.Address|String|The email address of the account.|
|Account.Username|String|The username of the account.|
|Account.Groups|String|Groups to which the account belongs (integration specific). For example, for AD these are groups in which the account is a member.|
|Account.Domain|String|The domain of the account.|
|Account.OrganizationUnit|String|The Organization Unit (OU) of the account.|

 

##### Command Example

    !gmail-create-user email=user@demistodev.com first-name=John family-name=Snow password=WinterIsComing

##### Context Example

    {
        "Account": [
            {
                "CustomerId": "C02f0zfqw",
                "DisplayName": "John Snow",
                "Domain": "demistodev.com",
                "Email": {
                    "Address": "user@demistodev.com"
                },
                "Gmail": {
                    "Address": "user@demistodev.com"
                },
                "Group": "admin#directory#user",
                "Groups": "admin#directory#user",
                "ID": "117047108909890245378",
                "Type": "Google",
                "UserName": "John",
                "Username": "John",
                "VisibleInDirectory": null
            }
        ]
    }

##### Human Readable Output

### New User:

|**Type**|**ID**|**Username**|**DisplayName**|**Groups**|**CustomerId**|**Domain**|**Email**|
|:-------|:-----|:-----------|:--------------|:---------|:-------------|:---------|:--------|
|Google|117047108909890245378|John|John Snow|admin\#directory\#user|C02f0zfqw|demistodev.com|Address: user@demistodev.com|


### 12. Delete mail from a mailbox

* * * * *

Deletes an email in the user's mailbox.

##### Base Command

`gmail-delete-mail`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The special value me can be used to indicate the authenticated user.|Required|
|message-id|The ID of the message to delete.|Required|
|permanent|Whether to delete the email permanently or move it to trash (default).|Optional|


##### Command Example

      !gmail-delete-mail user-id=admin@demistodev.com message-id=16d4316a25a332e4

##### Human Readable Output

Email has been successfully moved to trash.

### 13. Get message in an email thread

* * * * *

Returns all messages in a email thread.

##### Base Command

`gmail-get-thread`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The special value me can be used to indicate the authenticated user.|Required|
|thread-id|The ID of the thread to retrieve.|Required|
|format|The format in which to return the message. Can be: "full": Returns the full email message data with body content parsed in the payload field; the raw field is not used. (default) / "metadata": Returns only email message ID, labels, and email headers / "minimal": Returns only email message ID and labels; does not return the email headers, body, or payload / "raw": Returns the full email message data with body content in the raw field as a base64url encoded string; the payload field is not used|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Gmail.ID|string|Inner ID of the Gmail message.|
|Gmail.ThreadId|string|The thread ID.|
|Gmail.Format|string|MIME type of email.|
|Gmail.Labels|string|Labels of the specific email.|
|Gmail.To|string|Email Address of the receiver.|
|Gmail.From|string|Email Address of the sender.|
|Gmail.Cc|string|Additional recipient email address (CC).|
|Gmail.Bcc|string|Additional recipient email address (BCC).|
|Gmail.Subject|string|Subject of a specific email.|
|Gmail.Body|string|The content of the email.|
|Gmail.Attachments|unknown|The attachments of the email. IDs are separated by ','.|
|Gmail.Headers|unknown|All headers of the specific email (list).|
|Gmail.Mailbox|string|The Gmail Mailbox.|
|Email.To|String|The recipient of the email.|
|Email.From|String|The sender of the email.|
|Email.CC|String|Additional recipient email address (CC).|
|Email.BCC|String|Additional recipient email address (BCC).|
|Email.Format|String|The format of the email.|
|Email.Body/HTML|String|The HTML version of the email.|
|Email.Body/Text|String|The plain-text version of the email.|
|Email.Subject|String|The subject of the email.|
|Email.Headers|String|The headers of the email.|
|Email.Attachments.entryID|Unknown|Email Attachments. IDs are separated by ','.|
|Email.Date|String|The date the email was received.|


##### Command Example

      !gmail-get-thread user-id=admin@demistodev.com thread-id=16d4316a25a332e4

##### Context Example

    {
        "Email": [
            {
                "Attachment Names": "puppy.png",
                "Attachments": [
                    {
                        "ID": "",
                        "Name": "puppy.png"
                    }
                ],
                "BCC": "",
                "Body/HTML": "",
                "Body/Text": "",
                "CC": "",
                "Date": "Tue, 17 Sep 2019 23:36:59 -0700",
                "Format": "multipart/mixed",
                "From": "admin@demistodev.com",
                "Headers": [
                    {
                        "Name": "Received",
                        "Value": "from 1041831412594 named unknown by gmailapi.google.com with HTTPREST; Tue, 17 Sep 2019 23:36:59 -0700"
                    },
                    {
                        "Name": "Content-Type",
                        "Value": "multipart/mixed; boundary=\"===============3751607758919896682==\""
                    },
                    {
                        "Name": "MIME-Version",
                        "Value": "1.0"
                    },
                    {
                        "Name": "to",
                        "Value": "admin@demistodev.com"
                    },
                    {
                        "Name": "cc",
                        "Value": ""
                    },
                    {
                        "Name": "bcc",
                        "Value": ""
                    },
                    {
                        "Name": "from",
                        "Value": "admin@demistodev.com"
                    },
                    {
                        "Name": "subject",
                        "Value": "attachment"
                    },
                    {
                        "Name": "reply-to",
                        "Value": ""
                    },
                    {
                        "Name": "Date",
                        "Value": "Tue, 17 Sep 2019 23:36:59 -0700"
                    },
                    {
                        "Name": "Message-Id",
                        "Value": "<>"
                    }
                ],
                "ID": "16d4316a25a332e4",
                "RawData": null,
                "Subject": "attachment",
                "To": "admin@demistodev.com"
            }
        ],
        "Gmail": [
            {
                "Attachment Names": "puppy.png",
                "Attachments": [
                    {
                        "ID": "",
                        "Name": "puppy.png"
                    }
                ],
                "Bcc": "",
                "Body": "",
                "Cc": "",
                "Date": "Tue, 17 Sep 2019 23:36:59 -0700",
                "Format": "multipart/mixed",
                "From": "admin@demistodev.com",
                "Headers": [
                    {
                        "Name": "Received",
                        "Value": "from 1041831412594 named unknown by gmailapi.google.com with HTTPREST; Tue, 17 Sep 2019 23:36:59 -0700"
                    },
                    {
                        "Name": "Content-Type",
                        "Value": "multipart/mixed; boundary=\"===============3751607758919896682==\""
                    },
                    {
                        "Name": "MIME-Version",
                        "Value": "1.0"
                    },
                    {
                        "Name": "to",
                        "Value": "admin@demistodev.com"
                    },
                    {
                        "Name": "cc",
                        "Value": ""
                    },
                    {
                        "Name": "bcc",
                        "Value": ""
                    },
                    {
                        "Name": "from",
                        "Value": "admin@demistodev.com"
                    },
                    {
                        "Name": "subject",
                        "Value": "attachment"
                    },
                    {
                        "Name": "reply-to",
                        "Value": ""
                    },
                    {
                        "Name": "Date",
                        "Value": "Tue, 17 Sep 2019 23:36:59 -0700"
                    },
                    {
                        "Name": "Message-Id",
                        "Value": "<>"
                    }
                ],
                "Html": "",
                "ID": "16d4316a25a332e4",
                "Labels": "UNREAD, SENT, INBOX",
                "Mailbox": "admin@demistodev.com",
                "RawData": null,
                "Subject": "attachment",
                "ThreadId": "16d4316a25a332e4",
                "To": "admin@demistodev.com",
                "Type": "Gmail"
            }
        ]
    }

##### Human Readable Output

### Emails of Thread:

|**Mailbox**|**ID**|**Subject**|**From**|**To**|**Labels**|**Attachment Names**|**Format**|
|:----------|:-----|:----------|:-------|:-----|:---------|:-------------------|:---------|
|admin@demistodev.com|16d4316a25a332e4|attachment|admin@demistodev.com|admin@demistodev.com|UNREAD, SENT, INBOX|puppy.png|multipart/mixed|


### 14. Moves mail to a different folder

* * * * *

Moves an email to a different folder.

##### Base Command

`gmail-move-mail`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The special value me can be used to indicate the authenticated user.|Required|
|message-id|The ID of the message to retrieve.|Required|
|add-labels|Comma-separated list of labels to add to the email.|Optional|
|remove-labels|Comma separated list of labels to remove from the email.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Gmail.ID|string|Inner ID of the Gmail message.|
|Gmail.ThreadId|string|The thread ID.|
|Gmail.Format|string|MIME type of email.|
|Gmail.Labels|string|Labels of the specific email.|
|Gmail.To|string|Gmail address of the receiver.|
|Gmail.From|string|Gmail address of the sender.|
|Gmail.Cc|string|Additional recipient email address (CC).|
|Gmail.Bcc|string|Additional recipient email address (BCC).|
|Gmail.Subject|string|Subject of the specific email.|
|Gmail.Body|string|The content of the email.|
|Gmail.Attachments|unknown|The attachments of the email. IDs are separated by ','.|
|Gmail.Headers|unknown|All headers of the specific email (list).|
|Gmail.Mailbox|string|The Gmail mailbox.|
|Email.To|String|The recipient of the email.|
|Email.From|String|The sender of the email.|
|Email.CC|Unknown|Additional recipient email address (CC).|
|Email.BCC|Unknown|Additional recipient email address (BCC).|
|Email.Format|String|The format of the email.|
|Email.Body/HTML|String|The HTML version of the email.|
|Email.Body/Text|String|The plain-text version of the email.|
|Email.Subject|String|The subject of the email.|
|Email.Headers|String|The headers of the email.|
|Email.Attachments.entryID|Unknown|Email attachments. IDs are separated by ','.|
|Email.Date|String|The date the email was received.|


##### Command Example

      !gmail-move-mail user-id=admin@demistodev.com message-id=16d43097d9664008 add-labels=INBOX remove-labels=TRASH

##### Context Example

    {
        "Email": [
            {
                "Attachments": {
                    "entryID": ""
                },
                "BCC": [],
                "Body/HTML": null,
                "Body/Text": "",
                "CC": [],
                "Date": "",
                "Format": "",
                "From": null,
                "Headers": [],
                "ID": "16d43097d9664008",
                "RawData": null,
                "Subject": null,
                "To": null
            }
        ],
        "Gmail": [
            {
                "Attachments": "",
                "Bcc": [],
                "Body": "",
                "Cc": [],
                "Date": "",
                "Format": "",
                "From": null,
                "Headers": [],
                "Html": null,
                "ID": "16d43097d9664008",
                "Labels": "UNREAD, SENT, INBOX",
                "Mailbox": "admin@demistodev.com",
                "RawData": null,
                "Subject": null,
                "ThreadId": "16d43097d9664008",
                "To": null,
                "Type": "Gmail"
            }
        ]
    }

##### Human Readable Output

### Email:

|**Mailbox**|**ID**|**Labels**|
|:----------|:-----|:---------|
|admin@demistodev.com|16d43097d9664008|UNREAD, SENT, INBOX|


### 15. Move a mail to a different mailbox

* * * * *

Moves an email to a different mailbox.

##### Base Command

`gmail-move-mail-to-mailbox`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|src-user-id|The source user's email address. The special value me can be used to indicate the authenticated user.|Required|
|message-id|The ID of the message to retrieve.|Required|
|dst-user-id|The destination user's email address. The me special value can be used to indicate the authenticated user.|Required|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Gmail.ID|string|Inner ID of the Gmail message.|
|Gmail.ThreadId|string|The thread ID.|
|Gmail.Format|string|MIME type of email.|
|Gmail.Labels|string|Labels of the specific email.|
|Gmail.To|string|Gmail address of the receiver.|
|Gmail.From|string|Gmail address of the sender.|
|Gmail.Cc|string|Additional recipient email address (CC).|
|Gmail.Bcc|string|Additional recipient email address (BCC).|
|Gmail.Subject|string|Subject of the specific email.|
|Gmail.Body|string|The content of the email.|
|Gmail.Attachments|unknown|The attachments of the email. IDs are separated by ','.|
|Gmail.Headers|unknown|All headers of specific the email (list).|
|Gmail.Mailbox|string|The Gmail mailbox.|
|Email.To|String|The recipient of the email.|
|Email.From|String|The sender of the email.|
|Email.CC|String|Additional recipient email address (CC).|
|Email.BCC|String|Additional recipient email address (BCC).|
|Email.Format|String|The format of the email.|
|Email.Body/HTML|String|The HTML version of the email.|
|Email.Body/Text|String|The plain-text version of the email.|
|Email.Subject|String|The subject of the email.|
|Email.Headers|String|The headers of the email.|
|Email.Attachments.entryID|Unknown|Emails attachments. IDs are separated by ','.|
|Email.Date|String|The date the email was received.|

##### Command Example

      !gmail-move-mail-to-mailbox src-user-id=admin@demistodev.com message-id=16d4316a25a332e4 dst-user-id=test@demistodev.com

### 16. Add a rule to delete an email

* * * * *

Adds a rule for email deletion by address.

##### Base Command

`gmail-add-delete-filter`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The me special value can be used to indicate the authenticated user.|Required|
|email-address|Email address in which to block messages.|Required|

##### Command Example

      !gmail-add-delete-filter user-id=admin@demistodev.com email-address=test@demistodev.com

### 17. Add a new filter

* * * * *

Adds a new filter to the email.

##### Base Command

`gmail-add-filter`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The me special value can be used to indicate the authenticated user.|Required|
|from|The sender's display name or email address.|Optional|
|to|The recipient's display name or email address. Includes recipients in the "to", "cc", and "bcc" header fields. You can use the local part of the email address. For example, "example" and "example@" both match "example@gmail.com". This field is case-insensitive.|Optional|
|subject|The email subject.|Optional|
|query|Returns messages matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com is:unread".|Optional|
|has-attachments|Whether the message has any attachments.|Optional|
|size|The size of the entire RFC822 message in bytes, including all headers and attachments.|Optional|
|add-labels|Comma-separated list of labels to add to the message.|Optional|
|remove-labels|Comma-separated list of labels to remove from the message.|Optional|
|forward|Email address that the message is to be forwarded. The email needs to be configured as a forwarding address, see https://support.google.com/mail/answer/10957?hl=en#null.|Optional|
|size-comparison|The message size in bytes compared to the size field.|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|GmailFilter.ID|string|Filter ID.|
|GmailFilter.Mailbox|string|Mailbox containing the filter.|
|GmailFilter.Criteria|Unknown|Filter Criteria.|
|GmailFilter.Action|Unknown|Filter Action.|


##### Command Example

      !gmail-add-filter user-id=admin@demistodev.com has-attachments=true forward=test@demistodev.com subject=phishing

### 18. Get a list of filters in a mailbox

* * * * *

List all filters in a user's mailbox.

##### Base Command

`gmail-list-filters`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|User's email address. The "me" special value can be used to indicate the authenticated user.|Required|
|limit|Limit of the results list. Default is 100.|Optional|
|address|List filters associated with the email address.|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|GmailFilter.ID|string|Filter ID.|
|GmailFilter.Mailbox|string|Mailbox containing the filter.|
|GmailFilter.Criteria|Unknown|Filter Criteria.|
|GmailFilter.Action|Unknown|Filter Action.|


##### Command Example

      !gmail-list-filters user-id=me

##### Context Example

    {
        "GmailFilter": [
            {
                "Action": {
                    "addLabelIds": [
                        "TRASH"
                    ]
                },
                "Criteria": {
                    "from": ""
                },
                "ID": ",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "addLabelIds": [
                        "TRASH"
                    ]
                },
                "Criteria": {
                    "from": "test@demistodev.com"
                },
                "ID": "",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "forward": "test@demistodev.com"
                },
                "Criteria": {
                    "hasAttachment": true,
                    "subject": "phishing"
                },
                "ID": ",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "addLabelIds": [
                        "TRASH"
                    ]
                },
                "Criteria": {
                    "from": "JohnS1555841687807@demistodev.com"
                },
                "ID": ",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "addLabelIds": [
                        "CATEGORY_SOCIAL"
                    ]
                },
                "Criteria": {
                    "from": ""
                },
                "ID": "",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "addLabelIds": [
                        "TRASH"
                    ]
                },
                "Criteria": {
                    "from": ""
                },
                "ID": ",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "removeLabelIds": [
                        "INBOX"
                    ]
                },
                "Criteria": {
                    "to": ""
                },
                "ID": "",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "addLabelIds": [
                        "TRASH"
                    ]
                },
                "Criteria": {
                    "from": ""
                },
                "ID": ",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "addLabelIds": [
                        "TRASH"
                    ]
                },
                "Criteria": {
                    "from": "JohnS1555840057376@demistodev.com"
                },
                "ID": "",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "addLabelIds": [
                        "TRASH"
                    ]
                },
                "Criteria": {
                    "from": "JohnS1555841545018@demistodev.com"
                },
                "ID": "",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "addLabelIds": [
                        "TRASH"
                    ]
                },
                "Criteria": {
                    "from": "JohnS1555840196890@demistodev.com"
                },
                "ID": ",
                "Mailbox": "admin@demistodev.com"
            },
            {
                "Action": {
                    "addLabelIds": [
                        "TRASH"
                    ]
                },
                "Criteria": {
                    "from": "JohnS1555841616384@demistodev.com"
                },
                "ID": "",
                "Mailbox": "admin@demistodev.com"
            }
        ]
    }

##### Human Readable Output

### Filters:

|**ID**|**Criteria**|**Action**|
|:-----|:-----------|:---------|
| |from:|addLabelIds: TRASH|
| |from: test@demistodev.com|addLabelIds: TRASH|
| |hasAttachment: true <br/> subject: phishing|forward: test@demistodev.com|
| |from: JohnS1555841687807@demistodev.com|addLabelIds: TRASH|
| |from:|addLabelIds: CATEGORY\_SOCIAL|
| |from:|addLabelIds: TRASH|
| |to:|removeLabelIds: INBOX|
| |from:|addLabelIds: TRASH|
| |from: JohnS1555840057376@demistodev.com|addLabelIds: TRASH|
| |from: JohnS1555841545018@demistodev.com|addLabelIds: TRASH|
| |from: JohnS1555840196890@demistodev.com|addLabelIds: TRASH|
| |from: JohnS1555841616384@demistodev.com|addLabelIds: TRASH|


### 19. Remove a filter from a mailbox.

* * * * *

Removes a Filter from a user's mailbox.

##### Base Command

`gmail-remove-filter`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|User's email address. The "me" special value can be used to indicate the authenticated user.|Required|
|filter\_ids|Comma separated list of filter IDs (can be retrieve using \`gmail-list-filters\` command)|Required|


##### Command Example

      !gmail-remove-filter user-id=admin@demistodev.com filter_ids=

##### Human Readable Output

### 20. Move a mail to a different mailbox

* * * * *

Moves a mail to a different mailbox.

##### Base Command

`gmail-move-mail-to-mailbox`

|**Argument**|**Description**|
|:----------------|:--------------|
| src-user-id | The source user's email address. The special value ***me ***can be used to indicate the authenticated user. |
| message-id | The ID of the message to move. |
| dst-user-id | The destination user's email address. The special value ***me*** can be used to indicate the authenticated user. |

##### Context example

    {
        “Gmail”: {
        "Email": [
            {
                "ID": ,
                "ThreadId": ,
                "Format": "multipart/mixed",
                "Labels": "UNREAD, CATEGORY_PERSONAL, INBOX",
                "To": "example@demisto.com",
                "From": "example@demisto.com",
                "Cc": ,
                "Bcc": ,
                "Subject": “email subject”,
                "Body": "email body",
                "Headers" : [
            {
                       "Name": ,
                       "Value": ,
                   },
                   {
                       "Name": ,
                       "Value": ,
                   }
                ],
                "Attachments": [
                    {
                        "Name": ,
                        "ID": ,
                    }
                ],
                "Type": "Gmail",
            }
          ]
        }
    }

### 21. Hide a user's information 

* * * * *

Hide a user's contact information, such as email addresses, profile information, etc, in the Global Directory.

##### Base Command

`gmail-hide-user-in-directory`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The "me" special value can be used to indicate the authenticated user.|Required|
|visible-globally|Whether to hide the user's visibility in the Global Directory. Can be False to hide the user, True to show the user in the directory (default).|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Account.Type|String|The account type. For example, "AD", "LocalOS", "Google", "AppleID", and so on.|
|Account.ID|String|The unique ID for the account (integration specific). For AD accounts this is the Distinguished Name (DN).|
|Account.DisplayName|String|The display name.|
|Account.Email.Address|String|The email address of the account.|
|Account.Gmail.Address|Unknown|Email assigned with current account.|
|Account.Domain|String|The domain of the account.|
|Account.Username|String|The username of the account.|
|Account.OrganizationUnit|String|The Organization Unit (OU) of the account.|
|Account.VisibleInDirectory|Boolean|Whether the account is visible in the Global Directory.|
|Account.Groups|String|Groups in which the account belongs (integration specific). For example, for AD these are groups of which the account is member.|


##### Command Example

      !gmail-hide-user-in-directory user-id=user@demistodev.com visible-globally=false

##### Context Example

    {
        "Account": [
            {
                "CustomerId": "C02f0zfqw",
                "DisplayName": "John Snow",
                "Domain": "demistodev.com",
                "Email": {
                    "Address": "user@demistodev.com"
                },
                "Gmail": {
                    "Address": "user@demistodev.com"
                },
                "Group": "admin#directory#user",
                "Groups": "admin#directory#user",
                "ID": "117047108909890245378",
                "Type": "Google",
                "UserName": "John",
                "Username": "John",
                "VisibleInDirectory": false
            }
        ]
    }

##### Human Readable Output

### User user@demistodev.com:

|**Type**|**ID**|**Username**|**DisplayName**|**Groups**|**CustomerId**|**Domain**|**Email**|**VisibleInDirectory**|
|:-------|:-----|:-----------|:--------------|:---------|:-------------|:---------|:--------|:---------------------|
|Google|117047108909890245378|John|John Snow|admin\#directory\#user|C02f0zfqw|demistodev.com|Address: user@demistodev.com|false|

### 22. Set a password

* * * * *

Sets the password for the user.

##### Base Command

`gmail-set-password`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The special value me can be used to indicate the authenticated user.|Required|
|password|String formatted password for the user. Depends on the Password Policy of the Organization|Required|


##### Command Example

      !gmail-set-password user-id=user@demistodev.com password=new_password1!

##### Human Readable Output

User user@demistodev.com password has been set.

### 23. Get an auto reply message for the user

* * * * *

Returns the auto-reply message for the user's account.

##### Base Command

`gmail-get-autoreply`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The special value me can be used to indicate the authenticated user.|Required|

##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Account.Gmail.AutoReply.EnableAutoReply|Boolean|Flag that controls whether Gmail automatically replies to messages.|
|Account.Gmail.AutoReply.ResponseBody|String|Response body in plain text format.|
|Account.Gmail.AutoReply.ResponseSubject|String|Optional text to add to the subject line in vacation responses. To enable auto-replies, the response subject or the response body must not be empty.|
|Account.Gmail.AutoReply.RestrictToContact|String|Flag that determines whether responses are sent to recipients who are not in the user's list of contacts.|
|Account.Gmail.AutoReply.RestrcitToDomain|String|Flag that determines whether responses are sent to recipients who are outside of the user's domain. This feature is only available for G Suite users.|
|Account.Gmail.Address|String|Email assigned with the current account.|

##### Command Example

    !gmail-get-autoreply user-id=admin@demistodev.com

##### Context Example

    {
        "Account.Gmail": {
            "Address": "admin@demistodev.com",
            "AutoReply": [
                {
                    "EnableAutoReply": false,
                    "ResponseBody": "body_test",
                    "ResponseSubject": "subject_test",
                    "RestrictToContact": false,
                    "RestrictToDomain": false
                }
            ]
        }
    }

##### Human Readable Output

### User admin@demistodev.com:

|**EnableAutoReply**|**ResponseBody**|**ResponseSubject**|**RestrictToContact**|**RestrictToDomain**|
|:------------------|:---------------|:------------------|:--------------------|:-------------------|
|false|body_test|subject_test|false|false|


### 24. Set an auto-reply for the user

* * * * *

Sets the auto-reply for the user's account.

##### Base Command

`gmail-set-autoreply`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The "me" special value me can be used to indicate the authenticated user.|Required|
|enable-autoReply|Whether Gmail automatically replies to messages. Boolean. Set to true to automatically reply (default).|Optional|
|response-subject|Optional text to add to the subject line in vacation responses. To enable auto-replies, either the response subject or the response body must not be empty.|Optional|
|response-body|Response body in plain text format.|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Account.Gmail.AutoReply.EnableAutoReply|Boolean|Flag that controls whether Gmail automatically replies to messages.|
|Account.Gmail.AutoReply.ResponseBody|String|Response body in plain text format.|
|Account.Gmail.AutoReply.ResponseSubject|String|Optional text to add to the subject line in vacation responses. To enable auto-replies, either the response subject or the response body must not be empty.|
|Account.Gmail.AutoReply.RestrictToContact|String|Determines whether responses are sent to recipients who are not in the user's list of contacts.|
|Account.Gmail.AutoReply.RestrcitToDomain|String|Determines whether responses are sent to recipients who are outside of the user's domain. This feature is only available for G Suite users.|
|Account.Gmail.Address|String|Email assigned with the current account.|


##### Command Example

      !gmail-set-autoreply user-id=admin@demistodev.com enable-autoReply=false response-body=body_test response-subject=subject_test

##### Context Example

    {
        "Account.Gmail": {
            "Address": "admin@demistodev.com",
            "AutoReply": [
                {
                    "EnableAutoReply": false,
                    "ResponseBody": "body_test",
                    "ResponseSubject": "subject_test",
                    "RestrictToContact": false,
                    "RestrictToDomain": false
                }
            ]
        }
    }

##### Human Readable Output

### User admin@demistodev.com:

|**EnableAutoReply**|**ResponseBody**|**ResponseSubject**|**RestrictToContact**|**RestrictToDomain**|
|:------------------|:---------------|:------------------|:--------------------|:-------------------|
|false|body_test|subject_test|false|false|


### 25. Add a delegate user to a mailbox

* * * * *

Adds a delegate user to the mailbox, without sending any verification email. 

##### Base Command

`gmail-delegate-user-mailbox`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The "me" special value can be used to indicate the authenticated user.|Required|
|delegate-email|The email address of the delegate. The delegate user must be a member of the same G Suite organization as the delegator user and must be added using their primary email address, and not an email alias.|Required|

##### Command Example

      !gmail-delegate-user-mailbox delegate-email=shai@demistodev.com user-id=admin@demistodev.com

##### Human Readable Output

Email shai@demistodev.com has been delegated

### 26. Sends an email using Gmail

* * * * *

Sends an email using a Gmail account.

##### Base Command

`send-mail`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|to|Email addresses of the receiver.|Required|
|from|Email address of the sender.|Optional|
|body|The contents (body) of the email to be sent in plain text.|Optional|
|subject|Subject for the email to be sent.|Required|
|attachIDs|A comma-separated list of IDs of War Room entries that contain the files that need be attached to the email.|Optional|
|cc|Additional recipient email address (CC).|Optional|
|bcc|Additional recipient email address (BCC).|Optional|
|htmlBody|The contents (body) of the email to be sent in HTML format.|Optional|
|replyTo|Address that needs to be used to reply to the message.|Optional|
|attachNames|A comma-separated list of new names to rename attachments corresponding to the order that they were attached to the email. Examples - To rename first and third file attachNames=new\_fileName1,new\_fileName3 To rename second and fifth files attachNames=,new\_fileName2,new\_fileName5|Optional|
|attachCIDs|A comma-separated list of CID images to embed attachments inside the email.|Optional|
|transientFile|Textual name for an attached file. Multiple files are supported as a comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz")|Optional|
|transientFileContent|Content for the attached file. Multiple files are supported as a comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz")|Optional|
|transientFileCID|CID image for an attached file to include within the email body. Multiple files are supported as comma-separated list. (e.g. transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz")|Optional|
|additionalHeader|A CSV list of additional headers in the format: headerName=headerValue. For example: "headerName1=headerValue1,headerName2=headerValue2".|Optional|
|templateParams|Replaces {varname} variables with values from this parameter. Expected values are in the form of a JSON document. For example, {"varname" :{"value" "some value", "key": "context key"}}. Each var name can either be provided with the value or a context key to retrieve the value.|Optional|


##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Gmail.SentMail.ID|String|The immutable ID of the message.|
|Gmail.SentMail.Labels|String|List of IDs of labels applied to this message.|
|Gmail.SentMail.ThreadId|String|The ID of the thread in which the message belongs.|
|Gmail.SentMail.To|String|The recipient of the email.|
|Gmail.SentMail.From|Unknown|The sender of the email.|
|Gmail.SentMail.Cc|String|Additional recipient email address (CC).|
|Gmail.SentMail.Bcc|String|Additional recipient email address (BCC).|
|Gmail.SentMail.Subject|String|The subject of the email.|
|Gmail.SentMail.Body|Unknown|The plain-text version of the email.|
|Gmail.SentMail.MailBox|String|The mailbox from which the mail was sent.|


##### Command Example

      !send-mail subject="this is the subject" to=test@demistodev.com body="this is the body"

##### Context Example

    {
        "Gmail.SentMail": [
            {
                "Bcc": null,
                "Body": "this is the body",
                "Cc": null,
                "From": "admin@demistodev.com",
                "ID": "16d43287fc29b71a",
                "Labels": [
                    "SENT"
                ],
                "Mailbox": "test@demistodev.com",
                "Subject": "this is the subject",
                "ThreadId": "16d43287fc29b71a",
                "To": "test@demistodev.com",
                "Type": "Gmail"
            }
        ]
    }

##### Human Readable Output

### Email sent:

|**Type**|**ID**|**To**|**From**|**Subject**|**Body**|**Labels**|**ThreadId**|
|:-------|:-----|:-----|:-------|:----------|:-------|:---------|:-----------|
|Gmail|16d43287fc29b71a|test@demistodev.com|admin@demistodev.com|this is the subject|this is the body|SENT|16d43287fc29b71a|

### Reply to an email using Gmail
***
Reply to a mail using Gmail.

#### Base Command

`reply-mail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Email addresses of the receiver. | Required | 
| from | Email address of the sender. | Optional | 
| body | The contents (body) of the email to be sent in plain text. | Optional | 
| subject | Subject for the email to be sent. | Required | 
| inReplyTo | A comma-separated list of Message IDs to reply to. | Required | 
| references | A comma-separated list of Message IDs to refer to. | Optional | 
| attachIDs | A comma-separated list of IDs of War Room entries that contain the files that need be attached to the email. | Optional | 
| cc | Additional recipient email address (CC). | Optional | 
| bcc | Additional recipient email address (BCC). | Optional | 
| htmlBody | The contents (body) of the email to be sent in HTML format. | Optional | 
| replyTo | Address that needs to be used to reply to the message. | Required | 
| attachNames | A comma-separated list of new names to rename attachments corresponding to the order that they were attached to the email.<br/>        Examples - To rename first and third file attachNames=new_fileName1,,new_fileName3<br/>        To rename second and fifth files attachNames=,new_fileName2,,,new_fileName5 | Optional | 
| attachCIDs | A comma-separated list of CID images to embed attachments inside the email. | Optional | 
| transientFile | Textual name for an attached file. Multiple files are supported as a<br/>        comma-separated list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test<br/>        2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz") | Optional | 
| transientFileContent | Content for the attached file. Multiple files are supported as a comma-separated<br/>        list. For example, transientFile="t1.txt,temp.txt,t3.txt" transientFileContent="test<br/>        2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz") | Optional | 
| transientFileCID | CID image for an attached file to include within the email body. Multiple files are<br/>        supported as comma-separated list. (e.g. transientFile="t1.txt,temp.txt,t3.txt"<br/>        transientFileContent="test 2,temporary file content,third file content" transientFileCID="t1.txt@xxx.yyy,t2.txt@xxx.zzz") | Optional | 
| additionalHeader | A CSV list of additional headers in the format: headerName=headerValue. For example: "headerName1=headerValue1,headerName2=headerValue2". | Optional | 
| templateParams | 'Replaces {varname} variables with values from this parameter. Expected<br/>       values are in the form of a JSON document. For example, {"varname" :{"value" "some<br/>       value", "key": "context key"}}. Each var name can either be provided with<br/>       the value or a context key to retrieve the value.' | Optional | 


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


#### Command Example
``` !reply-mail subject="this is the subject" to=test@demistodev.com replyTo=test@demistodev.com body="this is the body" inReplyTo=<CAEvnzx+zEeFJ1U5g4FOfHKeWe-H3hU7kGiKaK7q0F0A@mail.gmail.com>```

##### Context Example

    {
        "Gmail.SentMail": [
            {
                "Bcc": null,
                "Body": "this is the body",
                "Cc": null,
                "From": "admin@demistodev.com",
                "ID": "16d43287fc29b71a",
                "Labels": [
                    "SENT"
                ],
                "Mailbox": "test@demistodev.com",
                "Subject": "this is the subject",
                "ThreadId": "16d43287fc29b71a",
                "To": "test@demistodev.com",
                "Type": "Gmail"
            }
        ]
    }

##### Human Readable Output

### Email sent:

|**Type**|**ID**|**To**|**From**|**Subject**|**Body**|**Labels**|**ThreadId**|
|:-------|:-----|:-----|:-------|:----------|:-------|:---------|:-----------|
|Gmail|16d43287fc29b71a|test@demistodev.com|admin@demistodev.com|this is the subject|this is the body|SENT|16d43287fc29b71a|

### 28. Removes a delegate from a mailbox

* * * * *

Removes a delegate user from the mailbox, without sending any verification email. 

##### Base Command

`gmail-remove-delegated-mailbox`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|user-id|The user's email address. The "me" special value can be used to indicate the authenticated user.|Required|
|removed-mail|The email address to remove from delegation. The delegate user must be a member of the same G Suite organization as the delegator user using their primary email address, and not an email alias.|Required|

##### Command Example

      !gmail-remove-delegated-mailbox removed-mail=shai@demistodev.com user-id=admin@demistodev.com

##### Human Readable Output

Email shai@demistodev.com has been removed from delegation

### 29. Get details of a specific role

* * * * *

Get details of a specific role.

##### Base Command

`gmail-get-role`

##### Input

|**Argument Name**|**Description**|**Required**|
|:----------------|:--------------|:-----------|
|role-id|The ID of the role.|Required|
|customer-id|Immutable Google Apps ID.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|:-------|:-------|:--------------|
|Gmail.Role.ETag|Unknown|The ETag of the resource.|
|Gmail.Role.IsSuperAdminRole|Boolean|Indicates whether the role is a super admin role or not.|
|Gmail.Role.IsSystemRole|Boolean|Indicates whether the role is a pre-defined system role or not.|
|Gmail.Role.Kind|String|The kind of the Role.|
|Gmail.Role.Description|String|The description of the role.|
|Gmail.Role.ID|String|The ID of the role.|
|Gmail.Role.Name|String|The name of the role.|
|Gmail.Role.Privilege.ServiceID|String|The ID of the service this privilege is for.|
|Gmail.Role.Privilege.Name|String|The name of the privilege.|

##### Command Example

`!gmail-get-role role-id=10740456929361923 customer-id=C02f0zfqw`

##### Context Example

    {
        "Gmail.Role": {
            "Description": "User Management Administrator",
            "ETag": "xW2YlxjdVEsAJNu_Hp5Dnespo8s/ZQw5R9B4LllVCDw22c-6qkEBmNk",
            "ID": "10740456929361923",
            "IsSuperAdminRole": false,
            "IsSystemRole": true,
            "Kind": "admin#directory#role",
            "Name": "_USER_MANAGEMENT_ADMIN_ROLE",
            "Privilege": [
                {
                    "Name": "USER_SECURITY_ALL",
                    "ServiceID": "00haapch16h1ysv"
                },
                {
                    "Name": "USERS_ALL",
                    "ServiceID": "00haapch16h1ysv"
                },
                {
                    "Name": "ADMIN_DASHBOARD",
                    "ServiceID": "01ci93xb3tmzyin"
                },
                {
                    "Name": "ORGANIZATION_UNITS_RETRIEVE",
                    "ServiceID": "00haapch16h1ysv"
                }
            ]
        }
    }

##### Human Readable Output

### Role 10740456929361923 details:

|**ETag**|**IsSuperAdminRole**|**IsSystemRole**|**Kind**|**Description**|**ID**|**Name**|
|:-------|:-------------------|:---------------|:-------|:--------------|:-----|:-------|
|xW2YlxjdVEsAJNu\_Hp5Dnespo8s/ZQw5R9B4LllVCDw22c-6qkEBmNk|false|true|admin\#directory\#role|User Management Administrator|10740456929361923|\_USER\_MANAGEMENT\_ADMIN\_ROLE|

### Role 10740456929361923 privileges:

|**ServiceID**|**Name**|
|:------------|:-------|
|00haapch16h1ysv|USER\_SECURITY\_ALL|
|00haapch16h1ysv|USERS\_ALL|
|01ci93xb3tmzyin|ADMIN\_DASHBOARD|
|00haapch16h1ysv|ORGANIZATION\_UNITS\_RETRIEVE|


