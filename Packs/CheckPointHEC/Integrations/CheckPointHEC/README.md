The Best Way to Protect Enterprise Email & Collaboration from phishing, malware, account takeover, data loss, etc.
This integration was integrated and tested with version 1.1.6 of CheckPointHEC

## Configure Check Point Harmony Email and Collaboration (HEC) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Smart API URL or Check Point Infinity API URL | The URL of the Smart API or Check Point Infinity API. | True |
| Fetch incidents | Enable fetching incidents from the selected SaaS application. | False |
| Incident type | Fetch incidents of the selected types. | False |
| Client ID | The client ID of the Smart API or Check Point Infinity API. | True |
| Client Secret | The client secret of the Smart API or Check Point Infinity API. | True |
| First fetch time | The time range for the first fetch. The default is 1 hour. | False |
| SaaS Application | Get incidents from the selected SaaS | False |
| State | Get incidents with only the selected states | False |
| Severity | Get incidents with only the selected severities | False |
| Threat Type | Get incidents with only the selected types | False |
| Maximum number of incidents per fetch | The maximum number of incidents to fetch per fetch. The default is 10. | False |
| Collect restore requests | Collect restore requests as incidents. | False |
| Trust any certificate (not secure) | Trust server certificate. | False |
| Use system proxy settings | Use system proxy settings. | False |
| Incidents Fetch Interval | The interval in minutes to fetch incidents. The default is 1 minute. | False |




## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
Action for one or more emails.

#### Base Command

`checkpointhec-send-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | One or multiple Email ids to apply action over. | Required | 
| saas | SaaS application to apply action over. Possible values are: Microsoft Exchange, Gmail. | Required | 
| action | Action to perform. Possible values are: quarantine, restore, decline_restore_request. | Required | 
| restore_decline_reason | Reason to decline restore request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.Task.task | String | Task id of the sent action. | 

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
### checkpointhec-get-ctp-list

***
Get Click Time Protection list.

#### Base Command

`checkpointhec-get-ctp-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List id to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.CTPList.listid | String | List id. | 
| CheckPointHEC.CTPList.listname | String | List name. | 
| CheckPointHEC.CTPList.listitem | String | List of items in the list. | 

### checkpointhec-delete-avurl-exceptions

***
Delete Avanan URL exceptions.

#### Base Command

`checkpointhec-delete-avurl-exceptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: allow-url, allow-domain, block-url, block-domain. | Required | 
| exc_str_list | List of exception strings to delete. | Required | 
| entity_type | Entity type. | Optional | 
| entity_id | Entity id. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-delete-avdlp-exception

***
Delete Avanan URL exception.

#### Base Command

`checkpointhec-delete-avdlp-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: hash, text_content, sender_email, recipient_email. | Required | 
| exc_str | Exception string. | Required | 
| entity_type | Entity type. | Optional | 
| entity_id | Entity id. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-get-anomaly-exceptions

***
Get Anomaly exceptions.

#### Base Command

`checkpointhec-get-anomaly-exceptions`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.AnomalyException.id | String | Anomaly exception id. | 
| CheckPointHEC.AnomalyException.anomaly_type | String | Anomaly type. | 
| CheckPointHEC.AnomalyException.insert_time | String | Anomaly exception creation time. | 
| CheckPointHEC.AnomalyException.update_time | String | Anomaly exception update time. | 
| CheckPointHEC.AnomalyException.added_by | String | Anomaly exception creator. | 
| CheckPointHEC.AnomalyException.event_id | String | Security event id. | 
| CheckPointHEC.AnomalyException.customer_domain | String | Customer domain. | 
| CheckPointHEC.AnomalyException.comments | String | Anomaly exception comment. | 
| CheckPointHEC.AnomalyException.enabled | Boolean | Anomaly exception enabled. | 
| CheckPointHEC.AnomalyException.exception_rule | String | Anomaly exception rule. | 
| CheckPointHEC.AnomalyException.expiration_date | String | Anomaly exception expiration date. | 

### checkpointhec-update-cp2-exception

***
Update Anti-Malware exception.

#### Base Command

`checkpointhec-update-cp2-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: hash, macro_hash, file_type, ppat_sender_name. | Required | 
| exc_str | Exception string. | Required | 
| comment | Exception comment. | Optional | 
| exc_payload_condition | Exception payload condition. Possible values are: with_or_without_link, with_link, without_link. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-create-avdlp-exception

***
Create Avanan DLP exception.

#### Base Command

`checkpointhec-create-avdlp-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: hash, text_content, sender_email, recipient_email. | Required | 
| exc_str | Exception string. | Required | 
| entity_type | Entity type. | Optional | 
| entity_id | Entity id. | Optional | 
| comment | Exception comment. | Optional | 
| exc_payload_condition | Exception payload condition. Possible values are: with_or_without_link, with_link, without_link. | Optional | 
| file_name | File name. | Optional | 
| created_by_email | Exception creator email. | Optional | 
| is_exclusive | Exclusive exception. Possible values are: yes, no. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-delete-ctp-list-items

***
Delete Click Time Protection list items.

#### Base Command

`checkpointhec-delete-ctp-list-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_item_ids | List of item ids to delete. | Required | 

#### Context Output

There is no context output for this command.
### checkpointhec-update-avdlp-exception

***
Update Avanan URL exception.

#### Base Command

`checkpointhec-update-avdlp-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: hash, text_content, sender_email, recipient_email. | Required | 
| exc_str | Exception string. | Required | 
| comment | Exception comment. | Optional | 
| exc_payload_condition | Exception payload condition. Possible values are: with_or_without_link, with_link, without_link. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-get-ap-exceptions

***
Get Anti-Phishing and Anti-Spam exceptions or exception.

#### Base Command

`checkpointhec-get-ap-exceptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | List name of exceptions to retrieve. Possible values are: whitelist, blacklist, spam_whitelist. | Required | 
| exc_id | Exception id to retrieve. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.AntiPhishingException.added_by | Number | Exception added by user id. | 
| CheckPointHEC.AntiPhishingException.affected_count | String | Affected count. | 
| CheckPointHEC.AntiPhishingException.allowed_links | String | Allowed links. | 
| CheckPointHEC.AntiPhishingException.attachment_md5 | String | Email attachment MD5. | 
| CheckPointHEC.AntiPhishingException.auto_classify_as | String | Auto classify as. | 
| CheckPointHEC.AntiPhishingException.comment | String | Exception description. | 
| CheckPointHEC.AntiPhishingException.customer_domain | String | Customer name. | 
| CheckPointHEC.AntiPhishingException.edited_by | String | Exception edited by. | 
| CheckPointHEC.AntiPhishingException.email_link | String | Email link. | 
| CheckPointHEC.AntiPhishingException.email_link_matching | String | Email link field condition. | 
| CheckPointHEC.AntiPhishingException.entity_id | Number | Entity id. | 
| CheckPointHEC.AntiPhishingException.exception_type | String | Exception type. | 
| CheckPointHEC.AntiPhishingException.expiration_time | String | Exception expiration time. | 
| CheckPointHEC.AntiPhishingException.from_domain | String | From domain. | 
| CheckPointHEC.AntiPhishingException.from_domain_ends_with | String | From domain field ends with. | 
| CheckPointHEC.AntiPhishingException.from_domain_matching | String | From domain field condition. | 
| CheckPointHEC.AntiPhishingException.from_email | String | Email sender. | 
| CheckPointHEC.AntiPhishingException.from_email_matching | String | From email field condition. | 
| CheckPointHEC.AntiPhishingException.from_name_matching | String | From name field condition. | 
| CheckPointHEC.AntiPhishingException.headers | String | Email headers. | 
| CheckPointHEC.AntiPhishingException.ignoring_spf_check | Boolean | Ignore SPF check. | 
| CheckPointHEC.AntiPhishingException.insert_time | String | Exception creation time. | 
| CheckPointHEC.AntiPhishingException.max_confidence | String | Maximum confidence. | 
| CheckPointHEC.AntiPhishingException.max_confidence_spam | String | Maximum confidence for spam. | 
| CheckPointHEC.AntiPhishingException.message_headers | String | Message headers. | 
| CheckPointHEC.AntiPhishingException.nickname | String | Sender name. | 
| CheckPointHEC.AntiPhishingException.owner_email | String | Exception owner email. | 
| CheckPointHEC.AntiPhishingException.override | Boolean | Override. | 
| CheckPointHEC.AntiPhishingException.recipient | String | Email recipient. | 
| CheckPointHEC.AntiPhishingException.recipient_matching | String | Recipient field condition. | 
| CheckPointHEC.AntiPhishingException.sender_client_ip | String | Sender client IP. | 
| CheckPointHEC.AntiPhishingException.sender_ip | String | Sender IP. | 
| CheckPointHEC.AntiPhishingException.signature_key | String | Signature key. | 
| CheckPointHEC.AntiPhishingException.subject | String | Email subject. | 
| CheckPointHEC.AntiPhishingException.subject_matching | String | Subject field condition. | 
| CheckPointHEC.AntiPhishingException.update_time | String | Exception update. | 
| CheckPointHEC.AntiPhishingException.user_label | String | User label. | 

### checkpointhec-create-avurl-exception

***
Create Avanan URL exception.

#### Base Command

`checkpointhec-create-avurl-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: allow-url, allow-domain, block-url, block-domain. | Required | 
| exc_str | Exception string. | Required | 
| entity_type | Entity type. | Optional | 
| entity_id | Entity id. | Optional | 
| comment | Exception comment. | Optional | 
| exc_payload_condition | Exception payload condition. Possible values are: with_or_without_link, with_link, without_link. | Optional | 
| file_name | File name. | Optional | 
| created_by_email | Exception creator email. | Optional | 
| is_exclusive | Exclusive exception. Possible values are: yes, no. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-get-avdlp-exceptions

***
Get Avanan DLP exceptions.

#### Base Command

`checkpointhec-get-avdlp-exceptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | List name of exceptions to retrieve. Possible values are: hash, text_content, sender_email, recipient_email. | Required | 
| filter_str | Search string. | Optional | 
| filter_index | Search index. Possible values are: insert_time, entity_type_id, exception_str, file_name, created_by_email, comment. | Optional | 
| sort_dir | Sort direction. Possible values are: asc, desc. | Optional | 
| last_evaluated_key | Last evaluated key. | Optional | 
| insert_time_gte | Insert time field condition. Possible values are: yes, no. | Optional | 
| limit | Number of exceptions to retrieve. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.AvananDLPException.insert_time | String | Exception insert time. | 
| CheckPointHEC.AvananDLPException.farm_customer_exception_type | String | Farm, customer and exception type info. | 
| CheckPointHEC.AvananDLPException.exception_str | String | Exception string, for id purposes. | 
| CheckPointHEC.AvananDLPException.created_by_email | String | Exception email creator. | 
| CheckPointHEC.AvananDLPException.comment | String | Exception comment. | 
| CheckPointHEC.AvananDLPException.exception_payload | String | Exception payload information. | 

### checkpointhec-delete-ctp-lists

***
Delete Click Time Protection lists.

#### Base Command

`checkpointhec-delete-ctp-lists`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### checkpointhec-create-anomaly-exception

***
Create Anomaly exception.

#### Base Command

`checkpointhec-create-anomaly-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_json | Anomaly exception request json. | Required | 
| added_by | User id exception creator. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-delete-cp2-exception

***
Delete Anti-Malware exception.

#### Base Command

`checkpointhec-delete-cp2-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: hash, macro_hash, file_type, ppat_sender_name. | Required | 
| exc_str | Exception string. | Required | 
| entity_type | Entity type. | Optional | 
| entity_id | Entity id. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-delete-anomaly-exceptions

***
Delete Anomaly exceptions.

#### Base Command

`checkpointhec-delete-anomaly-exceptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_ids | Exceptions to delete. | Required | 

#### Context Output

There is no context output for this command.
### checkpointhec-report-mis-classification

***
Report email mis-classification.

#### Base Command

`checkpointhec-report-mis-classification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entities | Email entity ids. | Required | 
| classification | New classification. Possible values are: Clean Email, Spam, Phishing, Legit Marketing Email. | Required | 
| confident | Confidence level. Possible values are: Not so sure, Medium Confidence, High Confidence. | Required | 

#### Context Output

There is no context output for this command.
### checkpointhec-get-avdlp-exception

***
Get Avanan DLP exception.

#### Base Command

`checkpointhec-get-avdlp-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | List name of exceptions to retrieve. Possible values are: hash, text_content, sender_email, recipient_email. | Required | 
| exc_str | Exception id to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.AvananDLPException.insert_time | String | Exception insert time. | 
| CheckPointHEC.AvananDLPException.farm_customer_exception_type | String | Farm, customer and exception type info. | 
| CheckPointHEC.AvananDLPException.exception_str | String | Exception string, for id purposes. | 
| CheckPointHEC.AvananDLPException.created_by_email | String | Exception email creator. | 
| CheckPointHEC.AvananDLPException.comment | String | Exception comment. | 
| CheckPointHEC.AvananDLPException.exception_payload | String | Exception payload information. | 

### checkpointhec-delete-ctp-list-item

***
Delete Click Time Protection list item.

#### Base Command

`checkpointhec-delete-ctp-list-item`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | Item id to delete. | Required | 

#### Context Output

There is no context output for this command.
### checkpointhec-get-ctp-list-item

***
Get Click Time Protection list item.

#### Base Command

`checkpointhec-get-ctp-list-item`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | Item id to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.CTPListItem.created_at | String | List item creation time. | 
| CheckPointHEC.CTPListItem.created_by | String | List item creator. | 
| CheckPointHEC.CTPListItem.listid | String | List id. | 
| CheckPointHEC.CTPListItem.listitemid | String | List item id. | 
| CheckPointHEC.CTPListItem.listitemname | String | List item name. | 
| CheckPointHEC.CTPListItem.listname | String | List name. | 

### checkpointhec-update-avurl-exception

***
Update Avanan URL exception.

#### Base Command

`checkpointhec-update-avurl-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: allow-url, allow-domain, block-url, block-domain. | Required | 
| exc_str | Exception string. | Required | 
| comment | Exception comment. | Optional | 
| exc_payload_condition | Exception payload condition. Possible values are: with_or_without_link, with_link, without_link. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-create-ctp-list-item

***
Create Click Time Protection list item.

#### Base Command

`checkpointhec-create-ctp-list-item`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List id. | Required | 
| list_item_name | List item name. | Required | 
| created_by | List item creator. | Required | 

#### Context Output

There is no context output for this command.
### checkpointhec-delete-ap-exception

***
Delete Anti-Phishing and Anti-Spam exception.

#### Base Command

`checkpointhec-delete-ap-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: whitelist, blacklist, spam_whitelist. | Required | 
| exc_id | Exception id. | Required | 

#### Context Output

There is no context output for this command.
### checkpointhec-delete-avurl-exception

***
Delete Avanan URL exception.

#### Base Command

`checkpointhec-delete-avurl-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: allow-url, allow-domain, block-url, block-domain. | Required | 
| exc_str | Exception string. | Required | 
| entity_type | Entity type. | Optional | 
| entity_id | Entity id. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-get-cp2-exception

***
Get Anti-Malware exception.

#### Base Command

`checkpointhec-get-cp2-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | List name of exceptions to retrieve. Possible values are: hash, macro_hash, file_type, ppat_sender_name. | Required | 
| exc_str | Exception id to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.AntiMalwareException.insert_time | String | Exception insert time. | 
| CheckPointHEC.AntiMalwareException.farm_customer_exception_type | String | Farm, customer and exception type info. | 
| CheckPointHEC.AntiMalwareException.exception_str | String | Exception string, for id purposes. | 
| CheckPointHEC.AntiMalwareException.created_by_email | String | Exception email creator. | 
| CheckPointHEC.AntiMalwareException.comment | String | Exception comment. | 
| CheckPointHEC.AntiMalwareException.exception_payload | String | Exception payload information. | 

### checkpointhec-update-ap-exception

***
Update Anti-Phishing and Anti-Spam exception.

#### Base Command

`checkpointhec-update-ap-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: whitelist, blacklist, spam_whitelist. | Required | 
| exc_id | Exception id. | Required | 
| entity_id | Entity id. | Optional | 
| attachment_md5 | Attachment MD5 checksum. | Optional | 
| from_email | Email sender. | Optional | 
| nickname | Sender name. | Optional | 
| recipient | Email recipient. | Optional | 
| sender_client_ip | Sender client IP. | Optional | 
| from_domain_ends_with | From domain ends with. | Optional | 
| sender_ip | Sender IP. | Optional | 
| email_link | Email link or links separated by comma. | Optional | 
| subject | Email subject. | Optional | 
| comment | Exception comment. | Optional | 
| action_needed | Action needed. | Optional | 
| ignoring_spf_check | Ignoring SPF check. | Optional | 
| subject_matching | Subject field condition. Possible values are: matching, contains, exact. | Optional | 
| email_link_matching | Email link field condition. Possible values are: matching, contains, exact. | Optional | 
| from_name_matching | From name field condition. Possible values are: matching, contains, exact. | Optional | 
| from_domain_matching | From domain field condition. Possible values are: contains, ends_with, exact. | Optional | 
| from_email_matching | From email field condition. Possible values are: matching, contains, exact. | Optional | 
| recipient_matching | Recipient field condition. Possible values are: matching, contains, exact. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-create-cp2-exception

***
Create Anti-Malware exception.

#### Base Command

`checkpointhec-create-cp2-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: hash, macro_hash, file_type, ppat_sender_name. | Required | 
| exc_str | Exception string. | Required | 
| entity_type | Entity type. | Optional | 
| entity_id | Entity id. | Optional | 
| comment | Exception comment. | Optional | 
| exc_payload_condition | Exception payload condition. Possible values are: with_or_without_link, with_link, without_link. | Optional | 
| file_name | File name. | Optional | 
| created_by_email | Exception creator email. | Optional | 
| is_exclusive | Exclusive exception. Possible values are: yes, no. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-delete-cp2-exceptions

***
Delete Anti-Malware exceptions.

#### Base Command

`checkpointhec-delete-cp2-exceptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: hash, macro_hash, file_type, ppat_sender_name. | Required | 
| exc_str_list | List of exception strings to delete. | Required | 
| entity_type | Entity type. | Optional | 
| entity_id | Entity id. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-get-ctp-lists

***
Get Click Time Protection lists.

#### Base Command

`checkpointhec-get-ctp-lists`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.CTPList.listid | String | List id. | 
| CheckPointHEC.CTPList.listname | String | List name. | 
| CheckPointHEC.CTPList.listitem | unknown | List item in the list. | 

### checkpointhec-update-ctp-list-item

***
Update Click Time Protection list item.

#### Base Command

`checkpointhec-update-ctp-list-item`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | Item id to update. | Required | 
| list_id | List id. | Required | 
| list_item_name | List item name. | Required | 
| created_by | List item creator. | Required | 

#### Context Output

There is no context output for this command.
### checkpointhec-create-ap-exception

***
Create Anti-Phishing and Anti-Spam exception.

#### Base Command

`checkpointhec-create-ap-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: whitelist, blacklist, spam_whitelist. | Required | 
| entity_id | Entity id. | Optional | 
| attachment_md5 | Attachment MD5 checksum. | Optional | 
| from_email | Email sender. | Optional | 
| nickname | Sender name. | Optional | 
| recipient | Email recipient. | Optional | 
| sender_client_ip | Sender client IP. | Optional | 
| from_domain_ends_with | From domain ends with. | Optional | 
| sender_ip | Sender IP. | Optional | 
| email_link | Email link or links separated by comma. | Optional | 
| subject | Email subject. | Optional | 
| comment | Exception comment. | Optional | 
| action_needed | Action needed. | Optional | 
| ignoring_spf_check | Ignoring SPF check. | Optional | 
| subject_matching | Subject field condition. Possible values are: matching, contains, exact. | Optional | 
| email_link_matching | Email link field condition. Possible values are: matching, contains, exact. | Optional | 
| from_name_matching | From name field condition. Possible values are: matching, contains, exact. | Optional | 
| from_domain_matching | From domain field condition. Possible values are: contains, ends_with, exact. | Optional | 
| from_email_matching | From email field condition. Possible values are: matching, contains, exact. | Optional | 
| recipient_matching | Recipient field condition. Possible values are: matching, contains, exact. | Optional | 

#### Context Output

There is no context output for this command.
### checkpointhec-get-avurl-exceptions

***
Get Avanan URL exceptions.

#### Base Command

`checkpointhec-get-avurl-exceptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | List name of exceptions to retrieve. Possible values are: allow-url, allow-domain, block-url, block-domain. | Required | 
| filter_str | Search string. | Optional | 
| filter_index | Search index. Possible values are: insert_time, entity_type_id, exception_str, file_name, created_by_email, comment. | Optional | 
| sort_dir | Sort direction. Possible values are: asc, desc. | Optional | 
| last_evaluated_key | Last evaluated key. | Optional | 
| insert_time_gte | Insert time field condition. Possible values are: yes, no. | Optional | 
| limit | Number of exceptions to retrieve. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.AvananURLException.insert_time | String | Exception insert time. | 
| CheckPointHEC.AvananURLException.farm_customer_exception_type | String | Farm, customer and exception type info. | 
| CheckPointHEC.AvananURLException.exception_str | String | Exception string, for id purposes. | 
| CheckPointHEC.AvananURLException.created_by_email | String | Exception email creator. | 
| CheckPointHEC.AvananURLException.comment | String | Exception comment. | 
| CheckPointHEC.AvananURLException.exception_payload | String | Exception payload information. | 

### checkpointhec-get-ctp-list-items

***
Get Click Time Protection list items.

#### Base Command

`checkpointhec-get-ctp-list-items`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.CTPListItem.created_at | String | List item creation time. | 
| CheckPointHEC.CTPListItem.created_by | String | List item creator. | 
| CheckPointHEC.CTPListItem.listid | String | List id. | 
| CheckPointHEC.CTPListItem.listitemid | String | List item id. | 
| CheckPointHEC.CTPListItem.listitemname | String | List item name. | 
| CheckPointHEC.CTPListItem.listname | String | List name. | 

### checkpointhec-get-cp2-exceptions

***
Get Anti-Malware exceptions.

#### Base Command

`checkpointhec-get-cp2-exceptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | List name of exceptions to retrieve. Possible values are: hash, macro_hash, file_type, ppat_sender_name. | Required | 
| filter_str | Search string. | Optional | 
| filter_index | Search index. Possible values are: insert_time, entity_type_id, exception_str, file_name, created_by_email, comment. | Optional | 
| sort_dir | Sort direction. Possible values are: asc, desc. | Optional | 
| last_evaluated_key | Last evaluated key. | Optional | 
| insert_time_gte | Insert time field condition. Possible values are: yes, no. | Optional | 
| limit | Number of exceptions to retrieve. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.AntiMalwareException.insert_time | String | Exception insert time. | 
| CheckPointHEC.AntiMalwareException.farm_customer_exception_type | String | Farm, customer and exception type info. | 
| CheckPointHEC.AntiMalwareException.exception_str | String | Exception string, for id purposes. | 
| CheckPointHEC.AntiMalwareException.created_by_email | String | Exception email creator. | 
| CheckPointHEC.AntiMalwareException.comment | String | Exception comment. | 
| CheckPointHEC.AntiMalwareException.exception_payload | String | Exception payload information. | 

### checkpointhec-get-avurl-exception

***
Get Avanan URL exception.

#### Base Command

`checkpointhec-get-avurl-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | List name of exceptions to retrieve. Possible values are: allow-url, allow-domain, block-url, block-domain. | Required | 
| exc_str | Exception id to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.AvananURLException.insert_time | String | Exception insert time. | 
| CheckPointHEC.AvananURLException.farm_customer_exception_type | String | Farm, customer and exception type info. | 
| CheckPointHEC.AvananURLException.exception_str | String | Exception string, for id purposes. | 
| CheckPointHEC.AvananURLException.created_by_email | String | Exception email creator. | 
| CheckPointHEC.AvananURLException.comment | String | Exception comment. | 
| CheckPointHEC.AvananURLException.exception_payload | String | Exception payload information. | 

### checkpointhec-delete-avdlp-exceptions

***
Delete Avanan DLP exceptions.

#### Base Command

`checkpointhec-delete-avdlp-exceptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exc_type | Exception type. Possible values are: hash, text_content, sender_email, recipient_email. | Required | 
| exc_str_list | List of exception strings to delete. | Required | 
| entity_type | Entity type. | Optional | 
| entity_id | Entity id. | Optional | 

#### Context Output

There is no context output for this command.
