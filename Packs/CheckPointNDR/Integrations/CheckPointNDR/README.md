Collect network security events from Check Point Infinity NDR for your secured SaaS periodically
This integration was integrated and tested with version 1.1.0 of CheckPointNDR

## Configure Check Point Network Detection and Response (Infinity NDR) in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Infinity NDR API URL (e.g. <https://api.now.checkpoint.com>) | True |
| Client ID | True |
| Access Key | True |
| First fetch time | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Incidents Fetch Interval | False |

## Commands

You can execute these commands from the Cortex CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### check-point-ndr-fetch-insights

***
Retrieve all NDR Insights

#### Base Command

`check-point-ndr-fetch-insights`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Date and time from which to fetch insights. Default is Last 24 hours.| Optional | 
| create_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Optional | 


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
