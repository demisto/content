## Overview
---
Use the Proofpoint Protection Server integration to manage your email security appliances.

This integration was integrated and tested with version 8.11.12 of Proofpoint Protection Server.

Users must be assigned to the **podadmin** role to use this integration.

This integration does not support SAML protocol for authentication.

## Use Cases
---
1. Manage senders list.
2. Run operations on emails, such as release and download.
3. Manage quarantined messages and folder.


## Configure Proofpoint Protection Server on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Proofpoint Protection Server.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g., https://192.168.0.1:10000)__
    * __Username__
    * __Password__
    * __Proofpoint Protection Server Version (e.g., 8.14.2)__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. proofpoint-download-email
2. proofpoint-quarantine-messages
3. proofpoint-smart-search
4. proofpoint-quarantine-folders
5. proofpoint-release-email
6. proofpoint-add-to-blocked-senders-list
7. proofpoint-add-to-safe-senders-list
8. proofpoint-remove-from-blocked-senders-list
9. proofpoint-remove-from-safe-senders-list

### 1. proofpoint-download-email
---
Download email message by ID.
##### Base Command

`proofpoint-download-email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The GUID of the email message to download. | Required |  


##### Context Output

There is no context output for this command.

##### Command Example
```!proofpoint-download-email message_id=37b6d02m-63e0-495e-kk92-7c21511adc7a@SB2APC01FT091.outlook.com```


### 2. proofpoint-quarantine-messages
---
Retrieves quarantined email messages.

##### Base Command

`proofpoint-quarantine-messages`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Folder name to quarantine. | Optional |
| sender | Messages from sender to quarantine. | Optional |
| subject | Messages subject to quarantine. | Optional |
| recipient | Messages to recipient to quarantine. | Optional |  

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.Quarantine.Message.ID | String | Message ID |
| Proofpoint.Quarantine.Message.Date | Date | Message date |
| Proofpoint.Quarantine.Message.Recipient | String | Message recipient |
| Proofpoint.Quarantine.Message.Sender | String | Message sender |
| Proofpoint.Quarantine.Message.Subject | String | Message subject |
| Proofpoint.Quarantine.Message.Folder | String | Message folder | 

##### Command Example
```!proofpoint-quarantine-messages recipient=user1@demisto.com```
##### Context Example
```
{
    "Proofpoint.Quarantine.Message": {
        "ID": "37b6d02m-63e0-495e-kk92-7c21511adc7a@SB2APC01FT091.outlook.com",
        "Date": "2020-01-25 11:30:00",
        "Recipient": "user1@demisto.com",
        "Sender": "bwillis@email.com",
        "Subject": "[External] Welcome !"
        "Folder": "Inbox
    }
}
```
##### Human Readable Output
### Proofpoint Protection Server Quarantine Search Messages Results
|ID|Date|Recipient|Sender|Subject|Folder|
|---|---|---|---|---|---|
| 37b6d02m-63e0-495e-kk92-7c21511adc7a@SB2APC01FT091.outlook.com | 2020-01-25 11:30:00 | user1@demisto.com | bwillis@email.com |External Welcome ! | Inbox |

### 3. proofpoint-smart-search
---
Searches for emails.

##### Base Command

`proofpoint-smart-search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process | Max results | Optional |
| sender | Email sender. | Optional |
| subject | Email subject. | Optional |
| recipient | Email recipient. | Optional |
| sender_hostname | Sender hostname/IP address | Optional |  
| attachment | Attachment name | Optional |
| qid | QID | Optional |
| time | Time period in which the email was recieved. | Optional |  
| message_id | Email message ID. | Optional |  
| virus_name | Virus name. | Optional |  
| sid | SID | Optional |  
| guid | GUID | Optional |  

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.SmartSearch.SMIMERecipients | String | Search results SMIME recipients |
| Proofpoint.SmartSearch.FID | String | Search results FID |
| Proofpoint.SmartSearch.MessageID | String | Search results email message ID |
| Proofpoint.SmartSearch.Suborg | String | Search results sub organization |
| Proofpoint.SmartSearch.Agent | String | Search results email agent |
| Proofpoint.SmartSearch.AttachmentNames | String | Search results email attachment names |
| Proofpoint.SmartSearch.MoudleID | String | Search results module ID |
| Proofpoint.SmartSearch.MessageSize | String | Search results email message size |
| Proofpoint.SmartSearch.SpamScore | String | Search results email spam score |
| Proofpoint.SmartSearch.GUID | String | Search results GUID |
| Proofpoint.SmartSearch.Recipients | String | Search results send mail to |
| Proofpoint.SmartSearch.Date | String | Search results date |
| Proofpoint.SmartSearch.Sender | String | Search results email sender |
| Proofpoint.SmartSearch.Subject | String | Search results email subject |


##### Command Example
```!proofpoint-smart-search recipient=user1@demisto.com process=100 time=Last24Hours```
##### Context Example
```
{
    "Proofpoint.SmartSearch": {
        "Date": "2020-01-25 11:30:00",
        "Recipients": "user1@demisto.com",
        "Sender": "bwillis@email.com",
        "Subject": "[External] Welcome !",
        "MessageSize": "20750"
    }
}
```
##### Human Readable Output
### Proofpoint Protection Server Smart Search Results
|ID|Date|Recipient|Sender|Subject|MessageSize|
|---|---|---|---|---|---|
| 37b6d02m-63e0-495e-kk92-7c21511adc7a@SB2APC01FT091.outlook.com | 2020-01-25 11:30:00 | user1@demisto.com | bwillis@email.com |External Welcome ! | 20750 |

### 4. proofpoint-quarantine-folders
---
Returns a list of quarantined folders.

##### Base Command

`proofpoint-quarantine-folders`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.Quarantine.Folder.Name | String | Folder name |

##### Command Example
```!proofpoint-quarantine-folders```
##### Context Example
```
{
    "Proofpoint.Quarantine.Folder": [
        {
            "Name": "Adult",
            "Name": "Audit",
            "Name": "Blocked",
            "Name": "Malware"
        }
    ]
}
```
##### Human Readable Output
### Proofpoint Protection Server Quarantine Folders
|Name|
|---|
| Adult |
| Audit |
| Blocked |
| Malware |

### 5. proofpoint-release-email
---
Release email with virus scan
##### Base Command

`proofpoint-download-email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Email message ID to release. | Required |  
| folder | Email folder to release. | Required |  


##### Context Output

There is no context output for this command.

##### Command Example
```!proofpoint-download-email message_id=37b6d02m-63e0-495e-kk92-7c21511adc7a@SB2APC01FT091.outlook.com folder=Blocked```

##### Human Readable Output
Released message 37b6d02m-63e0-495e-kk92-7c21511adc7a@SB2APC01FT091.outlook.com successfully

### 6. proofpoint-add-to-blocked-senders-list
---
Adds an email address to blocked senders list.
##### Base Command

`proofpoint-add-to-blocked-senders-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email to add to blocked senders list | Required |  

##### Context Output

There is no context output for this command.

##### Command Example
```!proofpoint-add-to-blocked-senders-list email=bwillis@email.com```

##### Human Readable Output
Successfully added bwillis@email.com to the Blocked Senders list

### 7. proofpoint-add-to-safe-senders-list
---
Adds an email address to safe senders list.
##### Base Command

`proofpoint-add-to-safe-senders-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email to add to safe senders list | Required |  

##### Context Output

There is no context output for this command.

##### Command Example
```!proofpoint-add-to-safe-senders-list email=bwillis@email.com```

##### Human Readable Output
Successfully added bwillis@email.com to the Safe Senders list

### 8. proofpoint-remove-from-blocked-senders-list
---
Removes an email address from blocked senders list.
##### Base Command

`proofpoint-remove-from-blocked-senders-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email to remove from blocked senders list | Required |  

##### Context Output

There is no context output for this command.

##### Command Example
```!proofpoint-remove-from-blocked-senders-list email=bwillis@email.com```

##### Human Readable Output
Successfully removed bwillis@email.com from the Blocked Senders list

### 8. proofpoint-remove-from-safe-senders-list
---
Removes an email address from safe senders list.
##### Base Command

`proofpoint-remove-from-safe-senders-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email to remove from safe senders list | Required |  

##### Context Output

There is no context output for this command.

##### Command Example
```!proofpoint-remove-from-safe-senders-list email=bwillis@email.com```

##### Human Readable Output
Successfully removed bwillis@email.com from the Safe Senders list



