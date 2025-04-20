Use Trend Micro Cloud App Security integration to protect against ransomware, phishing, malware, and unauthorized transmission of sensitive data for cloud applications, such as Microsoft 365, Box, Dropbox, Google G Suite and Salesforce.
## Configure TrendMicro Cloud App Security in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| serviceURL | Service URL | True |
| token | Token | True |
| isFetch | Fetch incidents | False |
| service | Service event to fetch | False |
| event_type | Event type to fetch | False |
| max_fetch | Maximum number of incidents per fetch | False |
| first_fetch | First fetch time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### trendmicro-cas-security-events-list
***
Retrieves security event logs of services.


#### Base Command

`trendmicro-cas-security-events-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service | Name of the protected service whose logs you want to retrieve. Can be: "exchange", "sharepoint", "onedrive", "dropbox", "box", "googledrive", "gmail", "teams", or "exchangeserver". | Required | 
| event_type | Type of the security event whose logs you want to retrieve. Can be: "securityrisk", "virtualanalyzer", "ransomware", or "dlp". | Required | 
| start | The start time to retrieve logs, using the date and time format ISO 8601. For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/>The request retrieves logs within a maximum of 72 hours before the request is sent.<br/>If a start time is added, the request retrieves all from the start time.<br/>If a start and end time are added, the request retrieves logs within the configured duration.<br/>If start and end times are not added, the request retrieves logs within 5 minutes before the request is sent.         | Optional | 
| end | The end time to retrieve logs, using the date and time format ISO 8601. For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/>The request retrieves logs within a maximum of 72 hours before request is sent.<br/>If an end time is added, the request retrieves logs within five minutes before the end time.<br/>If start and end are added, the request retrieves logs within the configured duration. Ensure the end time is no earlier than the start time.<br/>If the start and end times are not added, the request retrieves logs within 5 minutes before the request is sent.         | Optional | 
| limit | The maximum number of log items to display. Default is 50 and Maximum is 500. | Optional | 
| next_link | The URL for the results page if the total number of log items in a previous request exceeds the specified limit. When the maximum log items exceeds the limit, a URL is specified in the response. To retrieve the remaining log items, use the URL from the response. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroCAS.Events.last_log_item_generation_time | Date | The time and date when the last log item in the current request was generated. | 
| TrendMicroCAS.Events.next_link | String | URL for the follow\-up request if the requested logs exceed the specified limit to display at a time. Use this URL to form a second request. | 
| TrendMicroCAS.Events.security_events.event | String | The type of the requested security event. | 
| TrendMicroCAS.Events.security_events.log_item_id | String | The ID of a log item. | 
| TrendMicroCAS.Events.security_events.message.action | String | The action that Cloud App Security took after detecting the security event. | 
| TrendMicroCAS.Events.security_events.message.action_result | String | The result of the action. | 
| TrendMicroCAS.Events.security_events.message.affected_user | String | The Mailbox that received an email message triggering the security event, or the user account that uploaded or modified a file triggering the security event. | 
| TrendMicroCAS.Events.security_events.message.detected_by | String | The technology or method through which the email message or file triggering the security event was detected. | 
| TrendMicroCAS.Events.security_events.message.detection_time | Date | The time and date when the security event was detected. | 
| TrendMicroCAS.Events.security_events.message.location | String | The location where the security event was detected. | 
| TrendMicroCAS.Events.security_events.message.log_item_id | String | The ID of the log item. | 
| TrendMicroCAS.Events.security_events.message.mail_message_delivery_time | Date | The time and date when the email message triggering the security event was sent. | 
| TrendMicroCAS.Events.security_events.message.mail_message_file_name | String | The name of the email attachment that triggered the security event. | 
| TrendMicroCAS.Events.security_events.message.mail_message_id | String | The ID of the email message that triggered the security event. | 
| TrendMicroCAS.Events.security_events.message.mail_message_recipient | String | The Email address of the recipient. | 
| TrendMicroCAS.Events.security_events.message.mail_message_sender | String | The Email address of the sender. | 
| TrendMicroCAS.Events.security_events.message.mail_message_subject | String | The subject of the email message that triggered the security event. | 
| TrendMicroCAS.Events.security_events.message.mail_message_submit_time | Date | The time and date when the email message triggering the security event was received. | 
| TrendMicroCAS.Events.security_events.message.file_name | String | The name of the file that triggered the security event. | 
| TrendMicroCAS.Events.security_events.message.file_upload_time | Date | The time and date when the file triggering the security event was uploaded. | 
| TrendMicroCAS.Events.security_events.message.risk_level | String | The web reputation risk level assigned to the analyzed URL that triggered the security event. | 
| TrendMicroCAS.Events.security_events.message.scan_type | String | A real\-time scan or manual scan that detected the security event. | 
| TrendMicroCAS.Events.security_events.message.security_risk_name | String | The name of the security risk detected. | 
| TrendMicroCAS.Events.security_events.message.triggered_policy_name | String | The name of a configured policy that was violated. | 
| TrendMicroCAS.Events.security_events.message.triggered_security_filter | String | The name of the security filter that detected the security event. | 
| TrendMicroCAS.Events.security_events.message.virus_name | String | The name of the detected virus. | 
| TrendMicroCAS.Events.security_events.message.file_sha1 | String | The SHA\-1 hash value of the file that triggered the security event. | 
| TrendMicroCAS.Events.security_events.message.detection_type | String | The type of the suspicious object that triggered the security event. | 
| TrendMicroCAS.Events.security_events.message.ransomware_name | String | The name of the detected ransomware. | 
| TrendMicroCAS.Events.security_events.message.triggered_dlp_template | String | The details of the compliance template that was violated to trigger the security event. | 
| TrendMicroCAS.Events.security_events.service | String | The name of the requested service. | 
| TrendMicroCAS.Events.traceId | String | The randomly generated ID to trace the request. | 


#### Command Example
```!trendmicro-cas-security-events-list service=onedrive event_type=securityrisk start="1 day"```

#### Context Example
```
{
    "TrendMicroCAS": {
        "Events": [
            {
                "event": "security_risk_scan",
                "log_item_id": "b4f632b3-f797-45cb-aa28-207e6aa58a8d",
                "message": {
                    "action": "Quarantine",
                    "action_result": "success",
                    "affected_user": "ser@onmicrosoft.com",
                    "detected_by": "",
                    "detection_time": "2020-08-09T21:12:16.000Z",
                    "file_name": "20170813_125133.jpg",
                    "file_upload_time": "2020-08-09T09:11:58.000Z",
                    "location": "https://my.sharepoint.com/personal/onmicrosoft_com/Documents/",
                    "log_item_id": "b4f632b3-f797-45cb-aa28-207e6aa58a8d",
                    "risk_level": "",
                    "scan_type": "Real-time scan",
                    "security_risk_name": "20170813_125133.jpg",
                    "triggered_policy_name": "Default OneDrive Policy ATP",
                    "triggered_security_filter": "File Blocking"
                },
                "service": "OneDrive"
            },
            {
                "event": "security_risk_scan",
                "log_item_id": "e80363c5-29c8-4b0f-a3d0-748bc6bae263",
                "message": {
                    "action": "Quarantine",
                    "action_result": "success",
                    "affected_user": "ser@onmicrosoft.com",
                    "detected_by": "",
                    "detection_time": "2020-08-09T21:12:42.000Z",
                    "file_name": "20180802_144154.jpg",
                    "file_upload_time": "2020-08-09T09:12:19.000Z",
                    "location": "https://my.sharepoint.com/personal/onmicrosoft_com/Documents/",
                    "log_item_id": "e80363c5-29c8-4b0f-a3d0-748bc6bae263",
                    "risk_level": "",
                    "scan_type": "Real-time scan",
                    "security_risk_name": "20180802_144154.jpg",
                    "triggered_policy_name": "Default OneDrive Policy ATP",
                    "triggered_security_filter": "File Blocking"
                },
                "service": "OneDrive"
            },
            {
                "event": "security_risk_scan",
                "log_item_id": "89d50aab-0c34-4ffd-8497-62fbc1d51048",
                "message": {
                    "action": "Quarantine",
                    "action_result": "success",
                    "affected_user": "avishai@demistodev.onmicrosoft.com",
                    "detected_by": "",
                    "detection_time": "2020-08-09T21:12:46.000Z",
                    "file_name": "20180807190412.JPG",
                    "file_upload_time": "2020-08-09T09:12:23.000Z",
                    "location": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/Documents/",
                    "log_item_id": "89d50aab-0c34-4ffd-8497-62fbc1d51048",
                    "risk_level": "",
                    "scan_type": "Real-time scan",
                    "security_risk_name": "20180807190412.JPG",
                    "triggered_policy_name": "Default OneDrive Policy ATP",
                    "triggered_security_filter": "File Blocking"
                },
                "service": "OneDrive"
            }
        ]
    }
}
```

#### Human Readable Output

>### securityrisk events in onedrive
>|log_item_id|detection_time|security_risk_name|affected_user|action|action_result|
>|---|---|---|---|---|---|
>| b4f632b3-f797-45cb-aa28-207e6aa58a8d | 2020-08-09T21:12:16.000Z | 20170813_125133.jpg | avishai@demistodev.onmicrosoft.com | Quarantine | success |


### trendmicro-cas-email-sweep
***
Searches for email messages in mailboxes, matching search criteria.


#### Base Command

`trendmicro-cas-email-sweep`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mailbox | The Email address of the mailbox for which to search.<br/>A non-prefix wildcard is supported. For example, u*ser@gmail.com or user@gm*ail.com. | Optional | 
| lastndays | The number of days (n × 24 hours) before the request is sent to search.<br/>Do not configure lastndays and start/end at the same time. | Optional | 
| start | The start time to search for email messages using the date and time format ISO 8601. For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/>The request searches email messages according to the following settings:<br/>If both start and end are not added, the request searches email messages within seven days (7 × 24 hours) before the request was sent.<br/>If both start and end are added, the request searches email messages within this configured duration. Ensure the end time is no earlier than the start time.<br/>If only start is added, the request searches email messages within seven days (7 × 24 hours) after the start time.<br/>If only end is added, the request searches email messages within seven days (7 × 24 hours) before the end time.<br/>Do not configure lastndays and start/end at the same time. | Optional | 
| end | The end time to search for email messages using the date and time format ISO 8601. For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/>Cloud App Security saves the meta information of email messages for 90 days.<br/>The request searches email messages according to the following settings:<br/>If both start and end are not added, the request searches email messages within seven days (7 × 24 hours) before the request was sent.<br/>If both start and end are added, the request searches email messages within this duration. Ensure the end time is no earlier than the start time.<br/>If only start is added, the request searches email messages within seven days (7 × 24 hours) after the start time.<br/>If only end is added, the request searches email messages within seven days (7 × 24 hours) before the end time.<br/>Do not configure lastndays and start/end at the same time. | Optional | 
| subject | The subject of email messages for which to search. Use double quotes to search for an exact phrase, for example, "messageA messageB"<br/>otherwise a partial match based on the phrase is performed. For example, <br/>a search is performed on a subject containing messageA, or messageB, or messageA message B. | Optional | 
| file_sha1 | The SHA-1 hash value of the attachment file for which to search. | Optional | 
| file_name | The name of the attachment file for which to search, with or without a filename extension. A non-prefix wildcard is supported. For example, me*ssage. | Optional | 
| file_extension | The filename extension of attachment files for which to search without a period ".". A non-prefix wildcard is supported. For example, do* | Optional | 
| url | The URL contained in an email body or in an attachment for which to search. Type the<br/>full URL.  | Optional | 
| sender | The email address of the sender for which to search. Type the full email address. A non-prefix wildcard is supported. For example, u*ser@gmail.com. | Optional | 
| recipient | The email address of the recipient for which to search. Type the full email address. A non-prefix wildcard is supported. For example, u*ser@gmail.com. | Optional | 
| message_id | The Internet message ID of the email message for which to search.  Can be obtained from Microsoft Graph API or EWS API. | Optional | 
| source_ip | The Source IP address, with or without a subnet mask, of the email message to search. For example, xx.yy.zz.ww or xx.yy.zz.ww/16. | Optional | 
| source_domain | The Source domain of email messages for which to search. Type a complete domain name. A non-prefix wildcard is supported. For example, gm*ail.com. | Optional | 
| limit | The maximum number of email messages to display. Maximum is 1,000 email messages. If not specified, default is 20. | Optional | 
| next_link | The URL for the results page if the total number of email messages in a previous request exceeds the specified limit. When the maximum limit has been exceeded, a URL is specified in the response. To retrieve the remaining email messages, use the URL from the response. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroCAS.EmailSweep.next_link | String | URL for the follow\-up request if the requested email messages exceed the specified limit to display at a time. Use this URL to form a second request. | 
| TrendMicroCAS.EmailSweep.traceId | String | The randomly generated ID to trace the request. | 
| TrendMicroCAS.EmailSweep.value.mail_attachments.file_sha1 | String | The SHA\-1 hash value of the attachment file. | 
| TrendMicroCAS.EmailSweep.value.mail_attachments.file_name | String | The name of the attachment file. | 
| TrendMicroCAS.EmailSweep.value.mail_internet_headers.HeaderName | String | The Internet header name of the email address. | 
| TrendMicroCAS.EmailSweep.value.mail_internet_headers.Value | String | The email address of the sender. | 
| TrendMicroCAS.EmailSweep.value.mail_message_delivery_time | Date | The time and date when the email message was sent. | 
| TrendMicroCAS.EmailSweep.value.mail_message_id | String | The Internet message ID of the email message. | 
| TrendMicroCAS.EmailSweep.value.mail_message_recipient | String | A list of recipient email addresses of the email message. | 
| TrendMicroCAS.EmailSweep.value.mail_message_sender | String | The email address of the sender. | 
| TrendMicroCAS.EmailSweep.value.mail_message_subject | String | The subject of the email message. | 
| TrendMicroCAS.EmailSweep.value.mail_unique_id | String | The ID of the email message. | 
| TrendMicroCAS.EmailSweep.value.mail_urls | String | The URL contained in the email body or attachment. | 
| TrendMicroCAS.EmailSweep.value.mailbox | String | The mailbox which contains the email message. | 
| TrendMicroCAS.EmailSweep.value.source_domain | String | The source domain of the email message. | 
| TrendMicroCAS.EmailSweep.value.source_ip | String | The source IP address of the email message. | 


#### Command Example
```!trendmicro-cas-email-sweep lastndays=2 limit=2```

#### Context Example
```
{
    "TrendMicroCAS": {
        "EmailSweep": {
            "current_link": "https://api.tmcas.trendmicro.com/v1/sweeping/mails?lastndays=2&limit=2",
            "next_link": "https://api.tmcas.trendmicro.com/v1/sweeping/mails?lastndays=2&limit=2&skiptoken=WzE1OTY4NjA4MzEwMDAsIkFBTWtBR1kzT1RReU16TXpMV1l4TmprdE5ERTBNeTA1Tm1aaExXUTVNR1kxWWpJeU56QmtOQUJHQUFBQUFBQ1lDS2pXQW5YQlRybmhnV0pDY0xYN0J3RHJ4UndSanEtelRyTjZ2V1N6SzRPV0FBQUFBQUVKQUFEcnhSd1JqcS16VHJONnZXU3pLNE9XQUFPbjlyQzNBQUE9Il0=",
            "traceId": "3bedba23-c4da-47ba-a924-e6eec02d6110",
            "value": [
                {
                    "mail_attachments": [
                        {
                            "file_name": "report_Investigation_Summary_1596856796810442162.pdf",
                            "file_sha1": "53d27b284b324be18b2241f80cbc9ee4efd4684c"
                        }
                    ],
                    "mail_internet_headers": [
                        {
                            "HeaderName": "From",
                            "Value": "Build Tests <ser@onmicrosoft.com>"
                        },
                        {
                            "HeaderName": "Return-Path",
                            "Value": "ser@onmicrosoft.com"
                        },
                        {
                            "HeaderName": "Authentication-Results",
                            "Value": "spf=none (sender IP is 0.0.0.0)\r\n smtp.mailfrom=demisto.int;.onmicrosoft.com; dkim=none (message not\r\n signed) header.d=none;onmicrosoft.com; dmarc=none action=none\r\n header.from=int;compauth=softpass reason=201"
                        }
                    ],
                    "mail_message_delivery_time": "2020-08-08T03:20:53.000Z",
                    "mail_message_id": "<0d25a1993958467e92fe6243427e9c92@WIN-MICMSOEE1BU.demisto.int>",
                    "mail_message_recipient": [
                        "ser@onmicrosoft.com"
                    ],
                    "mail_message_sender": "ser@onmicrosoft.com",
                    "mail_message_subject": "Demisto Incident Summary Report",
                    "mail_unique_id": "AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEMAADrxRwRjq-zTrN6vWSzK4OWAAOn2KLJAAA=",
                    "mail_urls": [],
                    "mailbox": "ser@onmicrosoft.com",
                    "source_domain": "demisto.int",
                    "source_ip": "0.0.0.0"
                },
                {
                    "mail_attachments": [],
                    "mail_internet_headers": [
                        {
                            "HeaderName": "From",
                            "Value": "ser@onmicrosoft.com"
                        },
                        {
                            "HeaderName": "Return-Path",
                            "Value": "ser@onmicrosoft.com"
                        }
                    ],
                    "mail_message_delivery_time": "2020-08-08T04:27:11.000Z",
                    "mail_message_id": "<VI1PR07MB577569FD6DFA9073792BA49399460@VI1PR07MB5775.eurprd07.prod.outlook.com>",
                    "mail_message_recipient": [
                        "ser@onmicrosoft.com"
                    ],
                    "mail_message_sender": "ser@onmicrosoft.com",
                    "mail_message_subject": "Test mail from Demisto",
                    "mail_unique_id": "AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEJAADrxRwRjq-zTrN6vWSzK4OWAAOn9rC3AAA=",
                    "mail_urls": [],
                    "mailbox": "ser@onmicrosoft.com",
                    "source_domain": "onmicrosoft.com",
                    "source_ip": "0.0.0.0"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Search Results
>|mail_message_delivery_time|mail_message_id|mail_message_sender|mail_message_subject|mail_unique_id|mailbox|
>|---|---|---|---|---|---|
>| 2020-08-08T03:20:53.000Z | <0d25a1993958467e92fe6243427e9c92@WIN-MICMSOEE1BU.demisto.int> | buildtests@demisto.int | Demisto Incident Summary Report | AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEMAADrxRwRjq-zTrN6vWSzK4OWAAOn2KLJAAA= | ser@onmicrosoft.com |
>| 2020-08-08T04:27:11.000Z | <VI1PR07MB577569FD6DFA9073792BA49399460@VI1PR07MB5775.eurprd07.prod.outlook.com> | avishai@demistodev.onmicrosoft.com | Test mail from Demisto | AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEJAADrxRwRjq-zTrN6vWSzK4OWAAOn9rC3AAA= | ser@onmicrosoft.com |


### trendmicro-cas-user-take-action
***
Takes action on a batch of specified user accounts, such as disabling users accounts, 
requesting multi-factor authentication, and requesting to reset a password for users accounts.
Relevant for office365 exchange only.


#### Base Command

`trendmicro-cas-user-take-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_type | Action to take on a user's account. Can be: <br/>"ACCOUNT_DISABLE": Disables a user's account.<br/>"ACCOUNT_ENABLE_MFA": Enforces a user to perform a multi-factor authentication before being forced to change their password.<br/>"ACCOUNT_RESET_PASSWORD": Requests to reset the password for a user's account.<br/>NOTE: Before using ACCOUNT_ENABLE_MFA and ACCOUNT_RESET_PASSWORD, you need to assign the Administrator role to Cloud App Security.<br/>For more information, see https://docs.trendmicro.com/en-us/enterprise/cloud-app-security-integration-api-online-help/supported-cloud-app-_001/threat-mitigation-ap/take-actions-on-user/assigning-the-user-a.aspx. | Required | 
| account_user_email | Comma separated email addresses to take action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroCAS.UserTakeAction.action_type | String | The type of the action. | 
| TrendMicroCAS.UserTakeAction.account_user_email | String | The list of user accounts for the action. | 
| TrendMicroCAS.UserTakeAction.batch_id | String | The unique ID of the API request, including all actions to take on user accounts specified within this request. | 
| TrendMicroCAS.UserTakeAction.traceId | String | Randomly generated ID to uniquely trace the request. | 


#### Command Example
```!trendmicro-cas-user-take-action action_type=ACCOUNT_DISABLE account_user_email=ser@onmicrosoft.com```

#### Context Example
```
{
    "TrendMicroCAS": {
        "UserTakeAction": {
            "account_user_email": [
                "ser@onmicrosoft.com"
            ],
            "action_type": "ACCOUNT_DISABLE",
            "batch_id": "84266eaa-fe0b-4071-855d-423317a4c139",
            "traceId": "fb8aacbb-c6ab-4f99-825f-3a6f266cff15"
        }
    }
}
```

#### Human Readable Output

>### Action: ACCOUNT_DISABLE on users: ['avishai@demistodev.onmicrosoft.com'] was initiated
>|account_user_email|action_type|batch_id|traceId|
>|---|---|---|---|
>| ser@onmicrosoft.com | ACCOUNT_DISABLE | 84266eaa-fe0b-4071-855d-423317a4c139 | fb8aacbb-c6ab-4f99-825f-3a6f266cff15 |


### trendmicro-cas-email-take-action
***
Takes action on a batch of specified email messages, such as deleting and quarantining email messages.
Relevant for office365 exchange only.


#### Base Command

`trendmicro-cas-email-take-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_type | The action to take on an email message, such as delete or quarantine. Can be:<br/>"MAIL_DELETE", or "MAIL_QUARANTINE". | Required | 
| mailbox | The email address of an email message for which to take action. | Required | 
| mail_message_id | The Internet message ID of an email message for which to take action. <br/>To retrieve the ID, use the "trendmicro-cas-email-sweep" command. | Required | 
| mail_unique_id | The unique ID of an email message for which to take action.<br/>To retrieve the ID, use the "trendmicro-cas-email-sweep" command. | Required | 
| mail_message_delivery_time | The time and date when an email message sent<br/>To retrieve the information, use the "trendmicro-cas-email-sweep" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroCAS.EmailTakeAction.action_type | String | The type of action taken on an email message. | 
| TrendMicroCAS.EmailTakeAction.batch_id | String | The unique ID of the API request. | 
| TrendMicroCAS.EmailTakeAction.mailbox | String | The email address to take action. | 
| TrendMicroCAS.EmailTakeAction.traceId | String | Randomly generated ID to trace the request. | 


#### Command Example
```!trendmicro-cas-email-take-action action_type=MAIL_DELETE mail_message_delivery_time=2020-08-08T03:20:53.000Z mail_message_id=<0d25a1993958467e92fe6243427e9c92@WIN-MICMSOEE1BU.demisto.int> mail_unique_id=AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEMAADrxRwRjq-zTrN6vWSzK4OWAAOn2KLJAAA= mailbox=ser@onmicrosoft.com```

#### Context Example
```
{
    "TrendMicroCAS": {
        "EmailTakeAction": {
            "action_type": "MAIL_DELETE",
            "batch_id": "73534edc-011b-4318-a8ca-942af948434e",
            "mailbox": "ser@onmicrosoft.com",
            "traceId": "63c5ee4e-ec52-4124-9052-852e9f894f33"
        }
    }
}
```

#### Human Readable Output

>### Action: MAIL_DELETE on mailbox: avishai@demistodev.onmicrosoft.com was initiated
>|action_type|batch_id|mailbox|traceId|
>|---|---|---|---|
>| MAIL_DELETE | 73534edc-011b-4318-a8ca-942af948434e | ser@onmicrosoft.com | 63c5ee4e-ec52-4124-9052-852e9f894f33 |


### trendmicro-cas-user-action-result-query
***
Queries the results of actions taken on a user's account.


#### Base Command

`trendmicro-cas-user-action-result-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| batch_id | The unique ID of the action taken. Retrieve the ID from the "trendmicro-cas-email-take-action" command. | Optional | 
| start | The start time to retrieve action results within a time period, using the date and time format ISO 8601. For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/>If using start, end is required. | Optional | 
| end | The end time to retrieve action results within a time period, using the date and time format ISO 8601. For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/>If using end, start is required. Ensure the end time is not earlier than the start time. | Optional | 
| limit | The Maximum number of action results to display. Default (and maximum) is 500. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroCAS.UserActionResult.account_provider | String | The supplier of the protected service. | 
| TrendMicroCAS.UserActionResult.account_user_email | String | The email address on which the action was taken. | 
| TrendMicroCAS.UserActionResult.action_executed_at | Date | The time and date when the action was processed. | 
| TrendMicroCAS.UserActionResult.action_id | String | The unique ID of a threat mitigation task. | 
| TrendMicroCAS.UserActionResult.action_requested_at | Date | The time and date when the API request was received. | 
| TrendMicroCAS.UserActionResult.action_type | String | The action taken on a user's account. | 
| TrendMicroCAS.UserActionResult.batch_id | String | The unique ID of a Threat Mitigation API request. | 
| TrendMicroCAS.UserActionResult.error_code | Number | The result code of the action. | 
| TrendMicroCAS.UserActionResult.error_message | String | The string of the result code. For example, 0: success. | 
| TrendMicroCAS.UserActionResult.service | String | The name of the protected service. | 
| TrendMicroCAS.UserActionResult.status | String | The status of the action. Can be: "Created": The API request was received. "Executing": The action is executing. "Success": The action was successful. "Skipped": The action was skipped. "Failed": The action failed. | 


#### Command Example
```!trendmicro-cas-user-action-result-query batch_id=e9397872-9f6c-4c92-9bdc-45cc7fefaa86```

#### Context Example
```
{
    "TrendMicroCAS": {
        "UserActionResult": {
            "account_provider": "office365",
            "account_user_email": "ser@onmicrosoft.com",
            "action_executed_at": "2020-08-09T23:27:15.620Z",
            "action_id": "56222d76-5a49-4b73-aadd-7e8e439c7f10",
            "action_requested_at": "2020-08-09T23:27:12.216Z",
            "action_type": "ACCOUNT_DISABLE",
            "batch_id": "e9397872-9f6c-4c92-9bdc-45cc7fefaa86",
            "error_code": -999,
            "error_message": "graph api exception, message=One or more errors occurred.",
            "service": "exchange",
            "status": "Failed"
        }
    }
}
```

#### Human Readable Output

>### Action Result
>|action_id|status|action_type|account_user_email|action_executed_at|error_message|
>|---|---|---|---|---|---|
>| 56222d76-5a49-4b73-aadd-7e8e439c7f10 | Failed | ACCOUNT_DISABLE | ser@onmicrosoft.com | 2020-08-09T23:27:15.620Z | graph api exception, message=One or more errors occurred. |


### trendmicro-cas-email-action-result-query
***
Queries the results of actions taken for email messages.


#### Base Command

`trendmicro-cas-email-action-result-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| batch_id | The unique ID of the action taken. Retrieve the ID from the "trendmicro-cas-email-take-action" command. | Optional | 
| start | The start time to retrieve action results within a time period, using the date and time format ISO 8601. For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/>If using start, end is required.          | Optional | 
| end | The end time to retrieve action results within a time period, using the date and time format ISO 8601. For example, 2020-08-01T02:31:20Z or in human-readable format. For example, "in 1 day" or "3 weeks ago".<br/>If using end, start is required. Ensure the end time is not earlier than the start time. | Optional | 
| limit | The maximum number of action results to display. Default (and maximum) is 500. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroCAS.EmailActionResult.account_provider | String | The supplier of the protected service. | 
| TrendMicroCAS.EmailActionResult.account_user_email | String | The email address on which the action was taken. | 
| TrendMicroCAS.EmailActionResult.action_executed_at | Date | The time and date when the action was processed. | 
| TrendMicroCAS.EmailActionResult.action_id | String | The unique ID of a threat mitigation task. | 
| TrendMicroCAS.EmailActionResult.action_requested_at | Date | The time and date when the API request was received. | 
| TrendMicroCAS.EmailActionResult.action_type | String | The action taken on an email message. | 
| TrendMicroCAS.EmailActionResult.batch_id | String | The unique ID of a Threat Mitigation API request. | 
| TrendMicroCAS.EmailActionResult.error_code | Number | The result code of the action. | 
| TrendMicroCAS.EmailActionResult.error_message | String | The string of the result code. For example, 0: success. | 
| TrendMicroCAS.EmailActionResult.service | String | The name of the protected service, | 
| TrendMicroCAS.EmailActionResult.status | String | The status of the action. Can be: "Created": The API request was received. "Executing": The action is executing. "Success": The action was successful. "Skipped": The action was skipped. "Failed": The action failed. | 
| TrendMicroCAS.EmailActionResult.mail_unique_id | String | The unique ID of an email message on which an action was taken. | 
| TrendMicroCAS.EmailActionResult.mail_message_id | String | The Internet message ID of an email message on which an action was taken. | 
| TrendMicroCAS.EmailActionResult.mailbox | String | The email address of an email message on which an action was taken. | 


#### Command Example
```!trendmicro-cas-email-action-result-query batch_id=c3fba8cb-3736-4208-bf8b-a09e1aea9d9f```

#### Context Example
```
{
    "TrendMicroCAS": {
        "EmailActionResult": {
            "account_provider": "office365",
            "account_user_email": "ser@onmicrosoft.com",
            "action_executed_at": "2020-08-09T23:25:13.973Z",
            "action_id": "1c46ef63-04d8-46dc-a17d-653223c40728",
            "action_requested_at": "2020-08-09T23:25:12.943Z",
            "action_type": "MAIL_DELETE",
            "batch_id": "c3fba8cb-3736-4208-bf8b-a09e1aea9d9f",
            "error_code": 0,
            "error_message": "",
            "mail_message_id": "<0d25a1993958467e92fe6243427e9c92@WIN-MICMSOEE1BU.demisto.int>",
            "mail_unique_id": "AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEMAADrxRwRjq-zTrN6vWSzK4OWAAOn2KLJAAA=",
            "mailbox": "ser@onmicrosoft.com",
            "service": "exchange",
            "status": "Success"
        }
    }
}
```

#### Human Readable Output

>### Action Result
>|action_id|status|action_type|account_user_email|action_executed_at|error_message|
>|---|---|---|---|---|---|
>| 1c46ef63-04d8-46dc-a17d-653223c40728 | Success | MAIL_DELETE | ser@onmicrosoft.com | 2020-08-09T23:25:13.973Z |  |


### trendmicro-cas-blocked-lists-get
***
Retrieves all blocked senders, URLs, and SHA-1 hash values that have been configured to quarantine Exchange Online email messages.


#### Base Command

`trendmicro-cas-blocked-lists-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroCAS.BlockedList.filehashes | String | A list of blocked configured SHA\-1 hash values. | 
| TrendMicroCAS.BlockedList.senders | String | A list of configured blocked senders. | 
| TrendMicroCAS.BlockedList.urls | String | A list of blocked configured URLs. | 


#### Command Example
```!trendmicro-cas-blocked-lists-get```

#### Context Example
```
{
    "TrendMicroCAS": {
        "BlockedList": {
            "filehashes": [
                "f3cdddb37f6a933d6a256bd98b4bc703a448c621"
            ],
            "senders": [
                "456@gmail.com",
                "123@gmail.com"
            ],
            "urls": [
                "fttg.com/",
                "ubb.com/",
                "ggyu.com/"
            ]
        }
    }
}
```

#### Human Readable Output

>### Blocked List
>|filehashes|senders|urls|
>|---|---|---|
>| f3cdddb37f6a933d6a256bd98b4bc703a448c621 | 456@gmail.com,<br/>123@gmail.com | fttg.com/,<br/>ubb.com/,<br/>ggyu.com/ |


### trendmicro-cas-blocked-lists-update
***
Adds or removes senders, URLs, SHA-1 hash values to or from blocked lists. You must specify one of senders, urls, or filehashes.


#### Base Command

`trendmicro-cas-blocked-lists-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_type | The type of the action to take. Can be: "create", to add to the blocked lists, or<br/>"delete", to remove from the blocked lists. | Required | 
| senders | Comma separated email addresses from which the email message is sent to update.         | Optional | 
| urls | Comma separated URLs included in an email message to update.         | Optional | 
| filehashes | Comma separated SHA-1 hash values of an email attachment to update.         | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroCAS.BlockedList.filehashes | String | A list of blocked SHA\-1 hash values. | 
| TrendMicroCAS.BlockedList.senders | String | A list of blocked senders. | 
| TrendMicroCAS.BlockedList.urls | String | A list of blocked URLs. | 


#### Command Example
```!trendmicro-cas-blocked-lists-update action_type=create urls=ubb.com,ggyu.com filehashes=f3cdddb37f6a933d6a256bd98b4bc703a448c621 senders=123@gmail.com,456@gmail.com```

#### Context Example
```
{
    "TrendMicroCAS": {
        "BlockedList": {
            "filehashes": [
                "f3cdddb37f6a933d6a256bd98b4bc703a448c621"
            ],
            "senders": [
                "123@gmail.com",
                "456@gmail.com"
            ],
            "urls": [
                "ubb.com",
                "ggyu.com"
            ]
        }
    }
}
```

#### Human Readable Output

>### Add rules successfully.
>|filehashes|senders|urls|
>|---|---|---|
>| f3cdddb37f6a933d6a256bd98b4bc703a448c621 | 123@gmail.com,<br/>456@gmail.com | ubb.com,<br/>ggyu.com |
