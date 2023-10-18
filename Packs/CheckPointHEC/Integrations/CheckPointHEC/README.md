The Best Way to Protect Enterprise Email & Collaboration from phishing, malware, account takeover, data loss, etc.
This integration was integrated and tested with version 1.0.3 of CheckPointHEC

## Configure Check Point Harmony Email and Collaboration (HEC) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Check Point Harmony Email and Collaboration (HEC).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Smart API URL (e.g. https://smart-api-dev-1-us.avanan-dev.net) | True |
    | Fetch incidents | False |
    | Incident type | False |
    | Maximum number of incidents per fetch | False |
    | Client ID | True |
    | Client Secret | True |
    | First fetch time | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### checkpointhec-get-entity

***
Retrieve specific entity

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
| CheckPointHEC.Entity.subject | String | Email subject. | 
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
Get email ids with same sender and/or subject

#### Base Command

`checkpointhec-search-emails`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_range | Range to search for emails (1 day, 2 weeks, etc.). | Required | 
| sender | Search emails with this sender. | Optional | 
| subject | Search emails with this subject. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointHEC.SearchResult.ids | unknown | List of email ids returned by the search | 

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
