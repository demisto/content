The Best Way to Protect Enterprise Email & Collaboration from phishing, malware, account takeover, data loss, etc.
This integration was integrated and tested with version 1.1.3 of CheckPointHEC

## Configure Check Point Harmony Email and Collaboration (HEC) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Check Point Harmony Email and Collaboration (HEC).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Smart API URL or Check Point Infinity API URL |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Client ID |  | True |
    | Client Secret |  | True |
    | First fetch time |  | False |
    | SaaS Application | Get incidents from the selected SaaS | False |
    | State | Get incidents with only the selected states | False |
    | Severity | Get incidents with only the selected severities | False |
    | Threat Type | Get incidents with only the selected types | False |
    | Maximum number of incidents per fetch |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |

4. Click **Test** to validate the URLs, token, and connection.



## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### checkpointhec-get-entity

***
Retrieve specific entity.

#### Base Command

`checkpointhec-get-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Entity id to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.Entity.internetMessageId | String | Email message id in internet. | 
| CheckPointHEC.Entity.received | String | Datetime email was received in iso 8601 format. | 
| CheckPointHEC.Entity.size | String | Email size. | 
| CheckPointHEC.Entity.emailLinks | unknown | Links in email. | 
| CheckPointHEC.Entity.attachmentCount | Number | Number of attachments in email. | 
| CheckPointHEC.Entity.attachments | unknown | File attachments in email. | 
| CheckPointHEC.Entity.mode | String | Internal policy rule. | 
| CheckPointHEC.Entity.recipients | unknown | Recipient email addresses. | 
| CheckPointHEC.Entity.subject | String | Email subject. | 
| CheckPointHEC.Entity.fromEmail | String | Email sender. | 
| CheckPointHEC.Entity.fromDomain | String | Domain where the email was sent from. | 
| CheckPointHEC.Entity.fromUser | unknown | Sender user details. | 
| CheckPointHEC.Entity.fromName | String | Sender name. | 
| CheckPointHEC.Entity.to | unknown | Email main recipients. | 
| CheckPointHEC.Entity.toUser | unknown | User details for main recipients. | 
| CheckPointHEC.Entity.cc | unknown | Email carbon copy recipients. | 
| CheckPointHEC.Entity.ccUser | unknown | User details for carbon copy recipients. | 
| CheckPointHEC.Entity.bcc | unknown | Email blind carbon copy recipients. | 
| CheckPointHEC.Entity.bccUser | unknown | User details for blind carbon copy recipients. | 
| CheckPointHEC.Entity.replyToEmail | String | Email reply. | 
| CheckPointHEC.Entity.replyToNickname | String | Email reply nickname. | 
| CheckPointHEC.Entity.isRead | Boolean | Email has been read. | 
| CheckPointHEC.Entity.isDeleted | Boolean | Email has been deleted. | 
| CheckPointHEC.Entity.isIncoming | Boolean | Email is from external organization. | 
| CheckPointHEC.Entity.isInternal | Boolean | Email is from same organization. | 
| CheckPointHEC.Entity.isOutgoing | Boolean | Email is to an external organization. | 
| CheckPointHEC.Entity.isQuarantined | Boolean | Email has been quarantined. | 
| CheckPointHEC.Entity.isQuarantineNotification | Boolean | Email is a notification of another quarantined email. | 
| CheckPointHEC.Entity.isRestored | Boolean | Email is restored from quarantine. | 
| CheckPointHEC.Entity.isRestoreRequested | Boolean | Email is a request to restore. | 
| CheckPointHEC.Entity.isRestoreDeclined | Boolean | Email is a declined restore request. | 
| CheckPointHEC.Entity.saasSpamVerdict | String | Spam verdict. | 
| CheckPointHEC.Entity.SpfResult | String | Sender Policy Framework check result. | 
| CheckPointHEC.Entity.restoreRequestTime | String | Restore request datetime in iso 8601 format. | 
| CheckPointHEC.Entity.isUserExposed | Boolean | Email reached user inbox. | 


### checkpointhec-get-email-info

***
Retrieve specific email entity

#### Base Command

`checkpointhec-get-email-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Email entity id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.Email.fromEmail | String | Email sender. | 
| CheckPointHEC.Email.to | unknown | Email main recipients. | 
| CheckPointHEC.Email.replyToEmail | String | Email reply. | 
| CheckPointHEC.Email.replyToNickname | String | Email reply nickname. | 
| CheckPointHEC.Email.recipients | unknown | Recipient email addresses. | 
| CheckPointHEC.Email.subject | String | Email subject. | 
| CheckPointHEC.Email.cc | unknown | Email carbon copy recipients. | 
| CheckPointHEC.Email.bcc | unknown | Email blind carbon copy recipients. | 
| CheckPointHEC.Email.isRead | Boolean | Email has been read. | 
| CheckPointHEC.Email.received | String | Datetime email was received in iso 8601 format. | 
| CheckPointHEC.Email.isDeleted | Boolean | Email has been deleted. | 
| CheckPointHEC.Email.isIncoming | Boolean | Email is from external organization. | 
| CheckPointHEC.Email.isOutgoing | Boolean | Email is to an external organization. | 
| CheckPointHEC.Email.internetMessageId | String | Email message id in internet. | 
| CheckPointHEC.Email.isUserExposed | Boolean | Email reached user inbox | 

### checkpointhec-get-scan-info

***
Retrieve specific email scan with positive threats

#### Base Command

`checkpointhec-get-scan-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Scanned entity id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.ScanResult.ap | unknown | Anti-phishing scan results | 
| CheckPointHEC.ScanResult.dlp | unknown | Data Loss Prevention scan results | 
| CheckPointHEC.ScanResult.clicktimeProtection | unknown | Click Time Protection scan results | 
| CheckPointHEC.ScanResult.shadowIt | unknown | Shadow IT scan results | 
| CheckPointHEC.ScanResult.av | unknown | Antivirus scan results | 

### checkpointhec-search-emails

***
Search for emails.

#### Base Command

`checkpointhec-search-emails`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_last | Emails not older than (1 day, 2 weeks, etc.). The arguments `date_last` and `date_from` with `date_to` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| date_from | Start date to get emails in ISO 8601 format. The arguments `date_last` and `date_from` with `date_to` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| date_to | End date to get emails in ISO 8601 format. The arguments `date_last` and `date_from` with `date_to` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| saas | SaaS application to retrieve emails from. Possible values are: Microsoft Exchange, Gmail. | Optional | 
| direction | Email precedence. Possible values are: Internal, Incoming, Outgoing. | Optional | 
| subject_contains | Emails with subject containing the given value. The arguments `subject_contains` and `subject_match` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| subject_match | Emails with subject matching the given value. The arguments `subject_contains` and `subject_match` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| sender_contains | Emails with sender email containing the given value. The arguments `sender_contains` and `sender_match` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| sender_match | Emails with sender email matching the given value. The arguments `sender_contains` and `sender_match` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| domain | Emails with sender domain matching the given value. | Optional | 
| cp_detection | Detection by Check Point. Possible values are: Phishing, Suspected Phishing, Malware, Suspected Malware, Spam, Clean, DLP, Malicious URL Click, Malicious URL. | Optional | 
| ms_detection | Detection by Microsoft. Possible values are: Malware, High Confidence Phishing, Phishing, High Confidence Spam, Spam, Bulk, Clean. | Optional | 
| detection_op | Detection operator. Possible values are: OR, AND. | Optional | 
| server_ip | Sender server ip. | Optional | 
| recipients_contains | Emails with recipients containing the given value. The arguments `recipients_contains` and `recipients_match` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| recipients_match | Emails with recipients matching the given value. The arguments `recipients_contains` and `recipients_match` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| links | Emails with links in body matching the given value. | Optional | 
| message_id | Get specific email by id. | Optional | 
| cp_quarantined_state | Quarantine authored by Check Point. Possible values are: Quarantined (Any source), Not Quarantined, Quarantined by Check Point, Quarantined by CP Analyst, Quarantined by Admin. | Optional | 
| ms_quarantined_state | Quarantine authored by Microsoft. Possible values are: Quarantined, Not Quarantined, Not Quarantined Delivered to Inbox, Not Quarantined Delivered to Junk. | Optional | 
| quarantined_state_op | Quarantine state operator. Possible values are: OR, AND. | Optional | 
| name_contains | Emails with sender name containing the given value. The arguments `name_contains` and `name_match` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| name_match | Emails with sender name matching the given value. The arguments `name_contains` and `name_match` are mutually exclusive and cannot be specified together in the same request. | Optional | 
| client_ip | Sender client IP. | Optional | 
| attachment_md5 | Attachment MD5 checksum. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.Entity.internetMessageId | String | Email message id in internet. | 
| CheckPointHEC.Entity.received | String | Datetime email was received in iso 8601 format. | 
| CheckPointHEC.Entity.size | String | Email size. | 
| CheckPointHEC.Entity.emailLinks | unknown | Links in email. | 
| CheckPointHEC.Entity.attachmentCount | Number | Number of attachments in email. | 
| CheckPointHEC.Entity.attachments | unknown | File attachments in email. | 
| CheckPointHEC.Entity.mode | String | Internal policy rule. | 
| CheckPointHEC.Entity.recipients | unknown | Recipient email addresses. | 
| CheckPointHEC.Entity.subject | String | Email subject. | 
| CheckPointHEC.Entity.fromEmail | String | Email sender. | 
| CheckPointHEC.Entity.fromDomain | String | Domain where the email was sent from. | 
| CheckPointHEC.Entity.fromUser | unknown | Sender user details. | 
| CheckPointHEC.Entity.fromName | String | Sender name. | 
| CheckPointHEC.Entity.to | unknown | Email main recipients. | 
| CheckPointHEC.Entity.toUser | unknown | User details for main recipients. | 
| CheckPointHEC.Entity.cc | unknown | Email carbon copy recipients. | 
| CheckPointHEC.Entity.ccUser | unknown | User details for carbon copy recipients. | 
| CheckPointHEC.Entity.bcc | unknown | Email blind carbon copy recipients. | 
| CheckPointHEC.Entity.bccUser | unknown | User details for blind carbon copy recipients. | 
| CheckPointHEC.Entity.replyToEmail | String | Email reply. | 
| CheckPointHEC.Entity.replyToNickname | String | Email reply nickname. | 
| CheckPointHEC.Entity.isRead | Boolean | Email has been read. | 
| CheckPointHEC.Entity.isDeleted | Boolean | Email has been deleted. | 
| CheckPointHEC.Entity.isIncoming | Boolean | Email is from external organization. | 
| CheckPointHEC.Entity.isInternal | Boolean | Email is from same organization. | 
| CheckPointHEC.Entity.isOutgoing | Boolean | Email is to an external organization. | 
| CheckPointHEC.Entity.isQuarantined | Boolean | Email has been quarantined. | 
| CheckPointHEC.Entity.isQuarantineNotification | Boolean | Email is a notification of another quarantined email. | 
| CheckPointHEC.Entity.isRestored | Boolean | Email is restored from quarantine. | 
| CheckPointHEC.Entity.isRestoreRequested | Boolean | Email is a request to restore. | 
| CheckPointHEC.Entity.isRestoreDeclined | Boolean | Email is a declined restore request. | 
| CheckPointHEC.Entity.saasSpamVerdict | String | Spam verdict. | 
| CheckPointHEC.Entity.SpfResult | String | Sender Policy Framework check result. | 
| CheckPointHEC.Entity.restoreRequestTime | String | Restore request datetime in iso 8601 format. | 
| CheckPointHEC.Entity.isUserExposed | Boolean | Email reached user inbox. | 

### checkpointhec-send-action

***
Quarantine or restore an email

#### Base Command

`checkpointhec-send-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| farm | Customer farm. | Required | 
| customer | Customer portal name. | Required | 
| entity | One or multiple Email ids to apply action over. | Required | 
| action | Action to perform (quarantine or restore). Possible values are: quarantine, restore. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.Task.task | String | Task id of the sent action | 

### checkpointhec-get-action-result

***
Get task info related to a sent action

#### Base Command

`checkpointhec-get-action-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| farm | Customer farm. | Required | 
| customer | Customer portal name. | Required | 
| task | Task id to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.ActionResult.actions | unknown | Action information for each sent entity | 
| CheckPointHEC.ActionResult.created | String | Date when action was created in iso 8601 format | 
| CheckPointHEC.ActionResult.customer | String | Customer portal name | 
| CheckPointHEC.ActionResult.failed | Number | Number of failed actions | 
| CheckPointHEC.ActionResult.id | Number | Action task id | 
| CheckPointHEC.ActionResult.name | String | Action name | 
| CheckPointHEC.ActionResult.owner | String | Action owner | 
| CheckPointHEC.ActionResult.progress | Number | Number of actions in progress | 
| CheckPointHEC.ActionResult.sequential | Boolean | Actions are in sequence | 
| CheckPointHEC.ActionResult.status | String | Action status | 
| CheckPointHEC.ActionResult.succeed | Number | Number of succeed actions | 
| CheckPointHEC.ActionResult.total | Number | Total of actions | 
| CheckPointHEC.ActionResult.type | String | Action internal name | 
| CheckPointHEC.ActionResult.updated | String | Date when action last updated in iso 8601 format | 

### checkpointhec-send-notification

***
Send notification about user exposition for the specific entity to the list of emails

#### Base Command

`checkpointhec-send-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Email entity id. | Required | 
| emails | List of emails to send notification. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.Notification.ok | Boolean | Result of the operation. | 
### checkpointhec-get-events

***
Retrieve security events.

#### Base Command

`checkpointhec-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start date in ISO 8601 format. | Required | 
| end_date | End date in ISO 8601 format, now by default. | Optional | 
| saas_apps | SaaS application to retrieve events from. Possible values are: Microsoft Exchange, Gmail. | Optional | 
| states | Event states to be retrieved. Possible values are: New, Remediated, Detected, Exception, Dismissed. | Optional | 
| severities | Severity levels to be retrieved. Possible values are: Critical, High, Medium, Low, Very Low. | Optional | 
| threat_types | Threat types to be retrieved. Possible values are: DLP, Malware, Phishing, Anomaly, Suspicious Phishing, Suspicious Malware, Shadow IT, Alert, Spam, Malicious URL, Malicious URL Click. | Optional | 
| limit | Number of events to be returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.Event.eventId | String | Security event id. | 
| CheckPointHEC.Event.customerId | String | Customer portal name. | 
| CheckPointHEC.Event.saas | String | SaaS internal name. | 
| CheckPointHEC.Event.entityId | String | Email entity id related to the security event. | 
| CheckPointHEC.Event.state | String | Security event state. | 
| CheckPointHEC.Event.type | String | Security event threat type. | 
| CheckPointHEC.Event.confidenceIndicator | String | Security event threat type. | 
| CheckPointHEC.Event.eventCreated | String | Security event creation date. | 
| CheckPointHEC.Event.severity | String | Security event severity 1 - 5. | 
| CheckPointHEC.Event.description | String | Security event description. | 
| CheckPointHEC.Event.data | String | Security event data information. | 
| CheckPointHEC.Event.additionalData | String | Security event additional data information if available. | 
| CheckPointHEC.Event.availableEventActions | unknown | Actions available for the security event. | 
| CheckPointHEC.Event.actions | unknown | Performed actions related to the security event. | 
| CheckPointHEC.Event.senderAddress | String | Sender of email related to the security event. | 
| CheckPointHEC.Event.entityLink | String | Email link. | 
