# FireEye Email Threat Prevention (ETP)

## Overview
Use the FireEye Email Threat Prevention (ETP) integration to import messages as incidents, search for messages with specific attributes, and retrieve alert data.

## Use Cases
* Search for messages using specific message attributes as indicators.
* Import messages as Cortex XSOAR incidents, using the message status as indicator.

## Prerequisites
Make sure you obtain the following information.
* Valid FireEye ETP account
* Configure an API key on the ETP Web portal. Select the product as both *Email Threat Prevention* and *Identity Access Management*. Select all entitlements.
* Upon Authentication errors, contact FireEye Technical Support to let them know the IP address of your Cortex XSOAR Server and the URL you are accessing , e.g. https://etp.us.fireeye.com. FireEye will add these details to their Firewall rules so that the bidirectional traffic can be allowed between Cortex XSOAR and FireEye ETP.

## Configure FireEye ETP in Cortex

* *Name*: a textual name for the integration instance.
* *Server URL*: ETP server URL. Use the endpoint in the region that hosts your ETP service:
    * US instance: https://etp.us.fireeye.com
    * EMEA instance: https://etp.eu.fireeye.com
    * US GOV instance: https://etp.us.fireeyegov.com
* *API key*: The API key configured in the ETP Web Portal.
* *Messages status*: All status specified messages will be imported as incidents. Valid values are:
    * accepted
    * deleted
    * delivered
    * delivered (retroactive)
    * dropped
    * dropped oob
    * dropped (oob retroactive)
    * permanent failure
    * processing
    * quarantined
    * rejected
    * temporary failure

## Fetched Incidents Data
To use Fetch incidents:
1. Configure a new instance.
2. Navigate to *instance settings*, and specify the *message status* (using the valid values).
3. Select *Fetch incidents* option.

The integration will fetch alerts as incidents. It is possible to filter alerts using the specified message status.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. [Search for messages: fireeye-etp-search-messages](#search-for-messages)
2. [Get metadata of a specified message: fireeye-etp-get-message](#get-metadata-of-a-specified-message)
3. [Get summary of all alerts: fireeye-etp-get-alerts](#get-summary-of-all-alerts)
4. [Get details of a specified alert: fireeye-etp-get-alert](#get-details-of-specified-alert)

* * *

### Search for messages
Search for messages using specific message attributes as indicators.

##### Base Command

`fireeye-etp-search-messages`

##### Input

|Parameter|Description|More Information|
|---|---|---|
|from_email|List of sender email addresses|Maximum 10 arguments|
|from_email_not_in|List of sender email addresses to be excluded|Maximum 10 arguments
|recipients|List of recipient email addresses (including "cc")|Maximum 10 arguments
|recipients_not_in|list of recipient email addresses to be excluded (including "cc")|Maximum 10 arguments|
|subject|List of subjects in string format|Maximum 10 arguments|
|from_accepted_date_time|The start date of the search range, in time stamp format|For example, 2017-10-24T10:48:51.000Z|
|to_accepted_date_time|The end date of the search range, in time stamp format|For example, 2017-10-24T10:48:51.000Z|
|rejection_reason|List of ETP rejection-reason-codes|Valid rejection-reason-codes are: <ul><li>ETP102</li><li>ETP103</li><li>ETP104</li><li>ETP200</li><li>ETP201</li><li>ETP203</li><li>ETP204</li><li>ETP205</li><li>ETP300</li><li>ETP301</li><li>ETP302</li><li>ETP401</li><li>ETP402</li><li>ETP403</li><li>ETP404</li><li>ETP405</li></ul>
|sender_ip|List of sender IP addresses|Maximum of 10 arguments
|status|List of email status values|Valid statuses are:<ul><li>accepted</li><li>deleted</li><li>delivered</li><li>delivered (retroactive)</li><li>dropped</li><li>dropped oob</li><li>dropped (oob retroactive)</li><li>permanent failure</li><li>processing</li><li>quarantined</li><li>rejected</li></ul>|
|status_not_in|List of email status values to exclude|Valid statuses are:<ul><li>accepted</li><li>deleted</li><li>delivered</li><li>delivered (retroactive)</li><li>dropped</li><li>dropped oob</li><li>dropped (oob retroactive)</li><li>permanent failure</li><li>processing</li><li>quarantined</li><li>rejected</li></ul>|
|last_modified_date_time|Last modification date, in timestamp format, along with one of the following operators to indicate if to limit to before or after the specified date and time:<ul><li>></li><li><</li><li>>=</li><li><=</li></ul>|For example, to search for messages that were last modified before this specific date and time, use the following value:<br/><2017-10-24T18:00:00.000Z|
|domain|List of domain names|
|has_attachments|Indicates if the message has attachments|Boolean value|
|max_message_size|Maximum message size|Default value is 20 KB.<br/>Maximum value is 100 KB.|

##### Context Output

|Path|Description|
|---|---|
|FireEyeETP.Message.acceptedDateTime|Date and time that the message was accepted|
|FireEyeETP.Message.countryCode|Country code of sender|
|FireEyeETP.Message.domain|Domain|
|FireEyeETP.Message.emailSize|Email size in KB|
|FireEyeETP.Message.lastModifiedDateTime|Last modification date of message|
|FireEyeETP.Message.recipientHeader|List of message recipients display names and email addresses|
|FireEyeETP.Message.recipients|List of message recipients|
|FireEyeETP.Message.senderHeader|Display name and email address of the message sender|
|FireEyeETP.Message.sender|Email address of message sender|
|FireEyeETP.Message.senderSMTP|SMTP of Message sender|
|FireEyeETP.Message.senderIP|Message sender IP address|
|FireEyeETP.Message.status|Message status|
|FireEyeETP.Message.subject|Message subject|
|FireEyeETP.Message.verdicts.AS|Verdict for AS (pass/fail)|
|FireEyeETP.Message.verdicts.AV|Verdict for AV (pass/fail)|
|FireEyeETP.Message.verdicts.AT|Verdict for AT (pass/fail)|
|FireEyeETP.Message.verdicts.PV|Verdict for PV (pass/fail)|
|FireEyeETP.Message.id|Message ID|
 
##### Command example 1
`!fireeye-etp-search-messages to_accepted_date_time=2017-10- 24T10:00:00.000Z from_accepted_date_time=2017-10- 24T10:30:00.000Z`

##### Command example 2
`!fireeye-etp-search-messages from_email=diana@corp.com,charles@corp.com`

##### Raw Output
```json
{  
   "data": [  
      {  
         "attributes": {  
            "acceptedDateTime": "2018-06-09T10:49:32.000Z",
            "countryCode": "US",
            "domain": "test.com",
            "downStreamMsgID": "250 2.0.0 OK 100041373 d14-v6si970000qtb.70 - gsmtp",
            "emailSize": 9.89,
            "lastModifiedDateTime": "2018-06-09T10:49:33.329Z",
            "recipientHeader": [  
               "Security Operations Center <SOC@corp.com>"
            ],
            "recipientSMTP": [  
               "jason@demisto.com"
            ],
            "senderHeader": "\"soc@demisto.com\" <bot@demisto.com >",
            "senderSMTP": "prvs=691a94fds62a=demisto@demisto.com ",
            "senderIP": "***.***.***.***",
            "status": "delivered",
            "subject": "Attack TCP: SYN Host Sweep (Medium)",
            "verdicts": {  
               "AS": "",
               "AV": "",
               "AT": "pass",
               "PV": ""
            }
         },
         "included": [  
            {  
               "type": "domain",
               "id": 29074,
               "attributes": {  
                  "name": "test.com "
               }
            }
         ],
         "id": "C88B18749AAAAB1B55fc0fa78",
         "type": "trace"
      }
   ],
   "meta": {  
      "total": 85347,
      "copyright": "Copyright 2018 Fireeye Inc",
      "fromLastModifiedOn": {  
         "start": "2018-06-09T10:49:33.329Z",
         "end": "2018-06-09T10:50:59.034Z"
      }
   }
}
```

* * *

### Get metadata of a specified message
Get the metadata of a specified message.

#### Base Command
`fireeye-etp-get-message`

##### Input
|Parameter|Description|
|---|----|
|message_id|Message ID|
 
##### Context Output
|Path|Description|
|---|---|
|FireEyeETP.Message.acceptedDateTime|Date and time that the message was accepted|
|FireEyeETP.Message.countryCode|Country code of sender|
|FireEyeETP.Message.domain|Domain|
|FireEyeETP.Message.emailSize|Email size in KB|
|FireEyeETP.Message.lastModifiedDateTime|Message last modification date|
|FireEyeETP.Message.recipientHeader|List of message recipients display names and email addresses|
|FireEyeETP.Message.recipients|List of message recipients|
|FireEyeETP.Message.senderHeader|Display name and email address of the message sender|
|FireEyeETP.Message.sender|Message sender address|
|FireEyeETP.Message.senderSMTP|Message sender SMTP|
|FireEyeETP.Message.senderIP|Message sender IP address|
|FireEyeETP.Message.status|Message status|
|FireEyeETP.Message.subject|Message subject|
|FireEyeETP.Message.verdicts.AS|Verdict for AS (pass/fail)|
|FireEyeETP.Message.verdicts.AV|Verdict for AV (pass/fail)|
|FireEyeETP.Message.verdicts.AT|Verdict for AT (pass/fail)|
|FireEyeETP.Message.verdicts.PV|Verdict for PV (pass/fail)|
|FireEyeETP.Message.id|Message ID|
 
##### Command example
`!fireeye-etp-get-message message_id= C88B18749AAAAB1B55fc0fa78`

##### Raw Output
There is no raw output for this command.

### Get summary of all alerts
Get summary-format information about the alerts. Alerts that are more than 90 days old are not available.

##### Base Command
fireeye-etp-get-alerts

##### Input
|Parameter|Description|More Information|
|---|---|---|
|legacy_id|Alert ID as shown in ETP Web Portal|
|from_last_modified_on|Last modification date and time in the following format:<br/>yyy-mm-ddThh:mm:ss.fff|Default is last 90 days.|
|etp_message_id|Email message ID|
|size|Number of alerts intended in response|Default is 20.<br />Valid range is 1-100.|

##### Context Output
|Path|Description|
|---|---|
|FireEyeETP.Alerts.meta.read|Has the email been read?|
|FireEyeETP.Alerts.meta.last_modified_on|Last modification date in timestamp format|
|FireEyeETP.Alerts.meta.legacy_id|Alert ID as shown in ETP web portal|
|FireEyeETP.Alerts.alert.product|Product alerted|
|FireEyeETP.Alerts.alert.timestamp|Alert timestamp|
|FireEyeETP.Alerts.alert.malware_md5|MD5 of file attached|
|FireEyeETP.Alerts.email.status|Email status|
|FireEyeETP.Alerts.email.source_ip|Email source IP address|
|FireEyeETP.Alerts.email.smtp.rcpt_to|Recipient SMTP|
|FireEyeETP.Alerts.email.smtp.mail_from|Sender SMTP|
|FireEyeETP.Alerts.email.etp_message_id|Message ID|
|FireEyeETP.Alerts.email.headers.cc|Email 'cc' recipients|
|FireEyeETP.Alerts.email.headers.to|Email recipients|
|FireEyeETP.Alerts.email.headers.from|Email sender|
|FireEyeETP.Alerts.email.headers.subject|Email subject|
|FireEyeETP.Alerts.email.attachment|File name or URL pointing to file|
|FireEyeETP.Alerts.email.timestamp.accepted|Time the email was accepted|
|FireEyeETP.Alerts.id|Alert ID|
 
##### Command example
`!fireeye-etp-get-alerts legacy_id=50038117`

##### Raw Output
```json
{
  "data": [
    {
      "attributes": {
        "meta": {
          "read": false,
          "last_modified_on": "2018-04-02T22:28:46.133",
          "legacy_id": 50038117,
          "acknowledged": false
        },
        "ati": {},
        "alert": {
          "product": "ETP",
          "timestamp": "2018-04-02T22:28:41.328"
        },
        "email": {
          "status": "quarantined",
          "source_ip": "xx.xxx.xxx.xxx",
          "smtp": {
            "rcpt_to": "demisto@demisto.com",
            "mail_from": "bot@demisto.com"
          },
          "etp_message_id": "0103174000EA2CA54302e5ef",
          "headers": {
            "cc": "<birdperson@demisto.com>",
            "to": "< morty@demisto.com >",
            "from": " rick@demisto.com ",
            "subject": "[ CAT 6 ] DOHMH: Suspicious Activity Detected | 11810"
          },
          "attachment": "hxxp://xyzt.com/REX/slick.php?utma=gorc'",
          "timestamp": {
            "accepted": "2018-04-02T22:28:38"
          }
        },
      "id": "AWKIehnC9Y6JVVonz9xG",
      "links": {
        "detail": "/api/v1/alerts/AWKIehnC9Y6JVVonz9xG"
      }},
    "total": 109,
    "copyright": "Copyright 2018 Fireeye Inc"
  }],
  "type": "alerts"
}
```

* * *

### Get details of specified alert
Returns detailed information for any specified alert. Alerts that are more than 90 days old are not available.

##### Base Command
`fireeye-etp-get-alert`

##### Input
|Parameter|Description|
|---|---|
|alert_id|Alert ID|
 

##### Context Output
|Path|Description|
|---|---|
|FireEyeETP.Alerts.meta.read|Has the email been read?|
|FireEyeETP.Alerts.meta.last_modified_on|Last modification date in timestampformat|
|FireEyeETP.Alerts.meta.legacy_id|Alert ID as shown in ETP web portal|
|FireEyeETP.Alerts.meta.acknowledged|If acknowledged|
|FireEyeETP.Alerts.alert.product|Product that generated the alert|
|FireEyeETP.Alerts.alert.alert_typeA|Alert type code|
|FireEyeETP.Alerts.alert.severity|Severity code|
|FireEyeETP.Alerts.alert.explanation.analysis|Analysis|
|FireEyeETP.Alerts.alert.explanation.anomaly|Anomaly|
|FireEyeETP.Alerts.alert.explanation.malware_detected.malware.domain|Malware domain|
|FireEyeETP.Alerts.alert.explanation.malware_detected.malware.downloaded_at|Time malware was downloaded in timestamp format|
|FireEyeETP.Alerts.alert.explanation.malware_detected.malware.executed_at|Malware executed at timestamp|
|FireEyeETP.Alerts.alert.explanation.malware_detected.malware.name|Malware name|
|FireEyeETP.Alerts.alert.explanation.malware_detected.malware.sid|Malware SID|
|FireEyeETP.Alerts.alert.explanation.malware_detected.malware.stype|Malware type|
|FireEyeETP.Alerts.alert.explanation.malware_detected.malware.submitted_at|Where the malware was submitted|
|FireEyeETP.Alerts.alert.explanation.protocol|Protocol|
|FireEyeETP.Alerts.alert.explanation.timestamp|Explanation timestamp|
|FireEyeETP.Alerts.alert.timestamp|Alert timestamp|
|FireEyeETP.Alerts.alert.action|Alert action|
|FireEyeETP.Alerts.alert.name|Alert name|
|FireEyeETP.Alerts.email.status|Email status|
|FireEyeETP.Alerts.email.source_ip|Email source IP address|
|FireEyeETP.Alerts.email.smtp.rcpt_to|Recipient SMTP|
|FireEyeETP.Alerts.email.smtp.mail_from|Sender SMTP|
|FireEyeETP.Alerts.email.etp_message_id|FireEye ETP unique message ID|
|FireEyeETP.Alerts.email.headers.cc|Email cc recipients|
|FireEyeETP.Alerts.email.headers.to|Email recipients|
|FireEyeETP.Alerts.email.headers.from|Email sender|
|FireEyeETP.Alerts.email.headers.subject|Email subject|
|FireEyeETP.Alerts.email.attachment|File name or URL pointing to file|
|FireEyeETP.Alerts.email.timestamp.accepted|Time that the email was accepted|
|FireEyeETP.Alerts.id|The alert unique ID|  
 
##### Command example
`!fireeye-etp-get-alert alert_id= AWKMOs-2_r7_CWOc2okO`

##### Raw Output
```json
{  
   "data": [  
      {  
         "attributes": {  
            "meta": {  
               "read": false,
               "last_modified_on": "2018-04-03T15:58:07.280",
               "legacy_id": 52564988,
               "acknowledged": false
            },
            "ati": {  
               "data": {  

               }
            },
            "alert": {  
               "product": "ETP",
               "alert_type": [  
                  "at"
               ],
               "severity": "major",
               "ack": "no",
               "explanation": {  
                  "analysis": "binary",
                  "anomaly": "",
                  "cnc_services": {  

                  },
                  "malware_detected": {  
                     "malware": [  
                        {  
                           "domain": "xxx.xxx.xx.xxx",
                           "downloaded_at": "2018-04-03T15:57:58Z",
                           "executed_at": "2018-04-03T15:57:59Z",
                           "name": "Phish.LIVE.DTI.URL",
                           "sid": "88000012",
                           "stype": "known-url",
                           "submitted_at": "2018-04-03T15:57:58Z"
                        }
                     ]
                  },
                  "os_changes": [  

                  ],
                  "protocol": "",
                  "timestamp": "2018-04-03T15:57:59Z"
               },
               "timestamp": "2018-04-03T15:58:01.614",
               "action": "notified",
               "name": "malware-object"
            },
            "email": {  
               "status": "quarantined",
               "source_ip": "xx.xxx.xxx.xx",
               "smtp": {  
                  "rcpt_to": "demisto@demisto.com",
                  "mail_from": "bot@demisto.com"
               },
               "etp_message_id": "76CF1709028AAAA5d61a8dbe",
               "headers": {  
                  "cc": "\u003cbot@soc.com\u003e|\u003csoc@bot.com\u003e",
                  "to": "\u003cdemisto@demisto.com\u003e",
                  "from": "bot@demisto.com",
                  "subject": "[CAT 6] HRA: Suspicious Executable | 11819"
               },
               "attachment": "hxxp://xxx.xxx.xx.xxx/shop/ok.exe',([System.IO.Path]::GetTempPath()+'\\KQEW.exe')",
               "timestamp": {  
                  "accepted": "2018-04-03T15:57:55"
               }
            }
         },
         "id": "AWKMOs-2_r7_CWOc2okO"
      }
   ],
   "meta": {  
      "total": 1,
      "copyright": "Copyright 2017 Fireeye Inc."
   },
   "type": "alerts"
}
```

### fireeye-etp-download-yara-file

***
Downloads a YARA file.

#### Base Command

`fireeye-etp-download-yara-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_uuid | Universally unique identifier (UUID) of the policy. (Can be found on the URL of the ETP Policies). | Required | 
| ruleset_uuid | Universally unique identifier (UUID) of the ruleset. | Required | 

#### Context Output

There is no context output for this command.
### fireeye-etp-get-events-data

***
Returns all events of the alert by the alert ID.

#### Base Command

`fireeye-etp-get-events-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Message ID of alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeETP.Events | unknown | The events of the alert. | 
| FireEyeETP.Events.Delivered_msg | unknown | Display if event is delivered successfully or not. | 
| FireEyeETP.Events.Delivered_status | unknown | The status of the message. | 
| FireEyeETP.Events.InternetMessageId | unknown | The internet message ID of the alert. | 
| FireEyeETP.Events.Logs | unknown | The logs of the alert. | 

### fireeye-etp-list-yara-rulesets

***
Fetch the list of YARA rulesets and return a list with all the rules.

#### Base Command

`fireeye-etp-list-yara-rulesets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_uuid | Universally unique identifier (UUID) of the policy. (Can be found on the URL of the ETP Policies). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeETP.Policy | unknown | The policy id. | 

### fireeye-etp-upload-yara-file

***
Update or replace the YARA rule file in the existing ruleset.

#### Base Command

`fireeye-etp-upload-yara-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_uuid | Universally unique identifier (UUID) of the policy. (Can be found on the URL of the ETP Policies). | Required | 
| ruleset_uuid | Universally unique identifier (UUID) of the ruleset. | Required | 
| entryID | Entry ID of yara file to upload. | Required | 

#### Context Output

There is no context output for this command.
### fireeye-etp-download-alert-artifact

***
Downloads all case files of the alert specified by the alert ID, in a zip file. You can obtain the ID from the Alert Summary response, for example "id": "AV7zzRy7kvIwrKcfu0I".

#### Base Command

`fireeye-etp-download-alert-artifact`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID. | Required | 

#### Context Output

There is no context output for this command.
### fireeye-etp-quarantine-release

***
Releases the email file present in the quarantine for the given email. Cloud message ID.

#### Base Command

`fireeye-etp-quarantine-release`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The message ID. | Optional | 

#### Context Output

There is no context output for this command.
