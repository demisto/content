# Proofpoint TAP
Use the Proofpoint Targeted Attack Protection (TAP) integration to protect against and provide additional visibility into phishing and other malicious email attacks.
This integration was integrated and tested with version v2 of Proofpoint TAP v2
## Configure Proofpoint TAP v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | e.g., https://tap-api-v2.proofpoint.com | True |
| Service Principal | The password refers to secret | True |
| API Version | v1 is deprecated for new instances. The current API version is v2. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Threat type | A string specifying which threat type to return. If empty, all threat types are returned. Can be "url", "attachment", or "messageText". | False |
| Threat status | A string specifying which threat statuses to return. If empty, will return "active" and "cleared" threats. Can be "active", "cleared", or "falsePositive". | False |
| Events to fetch |  | False |
| Maximum number of incident per fetch |  | False |
| First fetch time range | First fetch time range \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 1 hour, 30 minutes\). Proofpoint supports a maximum 1 week fetch back. | False |
| Advanced: Raw message encoding | The character encoding to apply on the message fetched (e.g. latin-1). Advanced configuration to be used only if instructed by XSOAR Support | False |
| Fetch incidents |  | False |
| Incident type |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### proofpoint-get-events
***
Fetches events for all clicks and messages relating to known threats within the specified time period. Details as per clicks/blocked.


#### Base Command

`proofpoint-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval | A string containing an ISO8601-formatted interval. If this interval overlaps with previous requests for data, records from the previous request might be duplicated. The minimum interval is thirty seconds. The maximum interval is one hour. Examples: * 2016-05-01T12:00:00Z/2016-05-01T13:00:00Z - an hour interval, beginning at noon UTC on 05-01-2016 * PT30M/2016-05-01T12:30:00Z - the thirty minutes beginning at noon UTC on 05-01-2016 and ending at 12:30pm * UTC 2016-05-01T05:00:00-0700/PT30M - the same interval as above, but using -0700 as the time zone. | Optional | 
| threatType | A comma-separated list of the threat types to return. If empty, all threat types are returned. The following values are accepted: "url", "attachment", and "messageText". Possible values are: url, attachment, messageText. | Optional | 
| threatStatus | A string specifying which threat statuses to return. If empty, active and cleared threats are returned. Can be "active", "cleared", "falsePositive". Possible values are: active, cleared, falsePositive. | Optional | 
| sinceTime | A string containing an ISO8601 date. It represents the start of the data retrieval period. The end of the period is determined by the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result. Example: 2016-05-01T12:00:00Z. | Optional | 
| sinceSeconds | An integer representing a time window (in seconds) from the current API server time. The start of the window is the current API server time, rounded to the nearest minute, less the number of seconds provided. The end of the window is the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result. | Optional | 
| eventTypes | Event types to return. Possible values: "All", "Issues", "Delivered Messages", "Blocked Messages", "Permitted Clicks", and "Blocked Clicks". Possible values are: All, Issues, Delivered Messages, Blocked Messages, Permitted Clicks, Blocked Clicks. Default is All. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.MessagesDelivered.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS, which is unique. | 
| Proofpoint.MessagesDelivered.QID | String | The queue ID of the message within PPS. It can be used to identify the message in PPS, which is not unique. | 
| Proofpoint.MessagesDelivered.ccAddresses | String | A list of email addresses contained within the CC: header, excluding any friendly names. | 
| Proofpoint.MessagesDelivered.clusterId | String | The name of the PPS cluster which processed the message. | 
| Proofpoint.MessagesDelivered.fromAddress | String | The email address contained in the From: header, excluding any friendly name. | 
| Proofpoint.MessagesDelivered.headerCC | String | The CC header. | 
| Proofpoint.MessagesDelivered.headerFrom | String | The full content of the From: header, including any friendly name. | 
| Proofpoint.MessagesDelivered.headerReplyTo | String | If present, the full content of the Reply-To: header, including any friendly names. | 
| Proofpoint.MessagesDelivered.impostorScore | Number | The impostor score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.malwareScore | Number | The malware score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.messageId | String | Message-ID extracted from the headers of the email message. It can be used to look up the associated message in PPS, which is not unique. | 
| Proofpoint.MessagesDelivered.threatsInfoMap.threat | String | The artifact which was condemned by Proofpoint. The malicious URL, hash of the attachment threat, or email address of the impostor sender. | 
| Proofpoint.MessagesDelivered.threatsInfoMap.threatId | String | The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. | 
| Proofpoint.MessagesDelivered.threatsInfoMap.threatStatus | String | The current state of the threat \(active, expired, false-positive, cleared\). | 
| Proofpoint.MessagesDelivered.threatsInfoMap.threatTime | Date | The time Proofpoint assigned the threatStatus \(ISO8601 format\). | 
| Proofpoint.MessagesDelivered.threatsInfoMap.threatType | String | Whether the threat was an attachment, URL, or message type. | 
| Proofpoint.MessagesDelivered.threatsInfoMap.threatUrl | String | A link to the entry about the threat on the TAP Dashboard. | 
| Proofpoint.MessagesDelivered.messageTime | Date | The time the message was delivered to the user or quarantined by PPS. | 
| Proofpoint.MessagesDelivered.modulesRun | String | The list of PPS modules that processed the message. | 
| Proofpoint.MessagesDelivered.phishScore | Number | The phishing score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.policyRoutes | String | The policy routes that the message matched during processing by PPS. | 
| Proofpoint.MessagesDelivered.quarantineFolder | String | The name of the folder that contains the quarantined message. This appears only for messagesBlocked. | 
| Proofpoint.MessagesDelivered.quarantineRule | String | The name of the rule that quarantined the message. This appears only for messagesBlocked events. | 
| Proofpoint.MessagesDelivered.recipient | String | A list containing the email addresses of the recipients. | 
| Proofpoint.MessagesDelivered.replyToAddress | String | The email address contained in the Reply-To: header, excluding any friendly name. | 
| Proofpoint.MessagesDelivered.sender | String | The email address of the SMTP \(envelope\) sender. The user-part is hashed. The domain-part is cleartext. | 
| Proofpoint.MessagesDelivered.senderIP | String | The IP address of the sender. | 
| Proofpoint.MessagesDelivered.spamScore | Number | The spam score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.subject | String | The subject line of the message, if available. | 
| Proofpoint.MessagesBlocked.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS, which is unique. | 
| Proofpoint.MessagesBlocked.QID | String | The queue ID of the message within PPS. It can be used to identify the message in PPS, which is not unique. | 
| Proofpoint.MessagesBlocked.ccAddresses | String | A list of email addresses contained within the CC: header, excluding any friendly names. | 
| Proofpoint.MessagesBlocked.clusterId | String | The name of the PPS cluster that processed the message. | 
| Proofpoint.MessagesBlocked.fromAddress | String | The email address contained in the From: header, excluding any friendly name. | 
| Proofpoint.MessagesBlocked.headerCC | String | The CC header. | 
| Proofpoint.MessagesBlocked.headerFrom | String | The full content of the From: header, including any friendly name. | 
| Proofpoint.MessagesBlocked.headerReplyTo | String | If present, the full content of the Reply-To: header, including any friendly names. | 
| Proofpoint.MessagesBlocked.impostorScore | Number | The impostor score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesBlocked.malwareScore | Number | The malware score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesBlocked.messageId | String | Message-ID extracted from the headers of the email message. It can be used to look up the associated message in PPS, which is not unique. | 
| Proofpoint.MessagesBlocked.threatsInfoMap.threat | String | The artifact which was condemned by Proofpoint. The malicious URL, hash of the attachment threat, or email address of the impostor sender. | 
| Proofpoint.MessagesBlocked.threatsInfoMap.threatId | String | The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. | 
| Proofpoint.MessagesBlocked.threatsInfoMap.threatStatus | String | The current state of the threat \(active, expired, false-positive, cleared\). | 
| Proofpoint.MessagesBlocked.threatsInfoMap.threatTime | Date | The time Proofpoint assigned the threatStatus \(ISO8601 format\). | 
| Proofpoint.MessagesBlocked.threatsInfoMap.threatType | String | Whether the threat was an attachment, URL, or message type. | 
| Proofpoint.MessagesBlocked.threatsInfoMap.threatUrl | String | A link to the entry about the threat on the TAP dashboard. | 
| Proofpoint.MessagesBlocked.messageTime | Date | The time the message was blocked to the user or quarantined by PPS. | 
| Proofpoint.MessagesBlocked.messageTime | String | The list of PPS modules that processed the message. | 
| Proofpoint.MessagesBlocked.modulesRun | String | The list of PPS modules that processed the message. | 
| Proofpoint.MessagesBlocked.phishScore | Number | The phishing score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesBlocked.policyRoutes | String | The policy routes that the message matched during processing by PPS. | 
| Proofpoint.MessagesBlocked.quarantineFolder | String | The name of the folder that contains the quarantined message. This appears only for messagesBlocked. | 
| Proofpoint.MessagesBlocked.quarantineRule | String | The name of the rule that quarantined the message. This appears only for messagesBlocked events. | 
| Proofpoint.MessagesBlocked.recipient | String | A list containing the email addresses of the recipients. | 
| Proofpoint.MessagesBlocked.replyToAddress | String | The email address contained in the Reply-To: header, excluding any friendly name. | 
| Proofpoint.MessagesBlocked.sender | String | The email address of the SMTP \(envelope\) sender. The user-part is hashed. The domain-part is cleartext. | 
| Proofpoint.MessagesBlocked.senderIP | String | The IP address of the sender. | 
| Proofpoint.MessagesBlocked.spamScore | Number | The spam score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesBlocked.subject | String | The subject line of the message, if available. | 
| Proofpoint.ClicksPermitted.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS, which is unique. | 
| Proofpoint.ClicksPermitted.campaignId | String | An identifier for the campaign of which the threat is a member, if available at the time of the query. Threats can be linked to campaigns even after these events are retrieved. | 
| Proofpoint.ClicksPermitted.classification | String | The threat category of the malicious URL. | 
| Proofpoint.ClicksPermitted.clickIP | String | The external IP address of the user who clicked the link. If the user is behind a firewall performing network address translation, the IP address of the firewall will be shown. | 
| Proofpoint.ClicksPermitted.clickTime | Date | The time the user clicked the URL. | 
| Proofpoint.ClicksPermitted.messageID | String | The Message-ID extracted from the headers of the email message. It can be used to look up the associated message in PPS and is not unique. | 
| Proofpoint.ClicksPermitted.recipient | String | The email address of the recipient. | 
| Proofpoint.ClicksPermitted.sender | String | The email address of the sender. The user-part is hashed. The domain-part is cleartext. | 
| Proofpoint.ClicksPermitted.senderIP | String | The IP address of the sender. | 
| Proofpoint.ClicksPermitted.threatID | String | The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. | 
| Proofpoint.ClicksPermitted.threatTime | Date | The time Proofpoint identified the URL as a threat. | 
| Proofpoint.ClicksPermitted.threatURL | String | A link to the entry on the TAP Dashboard for the particular threat. | 
| Proofpoint.ClicksPermitted.url | String | The malicious URL which was clicked. | 
| Proofpoint.ClicksPermitted.userAgent | String | The User-Agent header from the clicker's HTTP request. | 
| Proofpoint.ClicksBlocked.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique. | 
| Proofpoint.ClicksBlocked.campaignId | String | An identifier for the campaign of which the threat is a member, if available at the time of the query. Threats can be linked to campaigns even after these events are retrieved. | 
| Proofpoint.ClicksBlocked.classification | String | The threat category of the malicious URL. | 
| Proofpoint.ClicksBlocked.clickIP | String | The external IP address of the user who clicked the link. If the user is behind a firewall performing network address translation, the IP address of the firewall will be shown. | 
| Proofpoint.ClicksBlocked.clickTime | Date | The time the user clicked the URL. | 
| Proofpoint.ClicksBlocked.messageID | String | Message-ID extracted from the headers of the email message. It can be used to look up the associated message in PPS and is not unique. | 
| Proofpoint.ClicksBlocked.recipient | String | The email address of the recipient. | 
| Proofpoint.ClicksBlocked.sender | String | The email address of the sender. The user-part is hashed. The domain-part is cleartext. | 
| Proofpoint.ClicksBlocked.senderIP | String | The IP address of the sender. | 
| Proofpoint.ClicksBlocked.threatID | String | The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. | 
| Proofpoint.ClicksBlocked.threatTime | Date | The time Proofpoint identified the URL as a threat. | 
| Proofpoint.ClicksBlocked.threatURL | String | A link to the entry on the TAP dashboard for the particular threat. | 
| Proofpoint.ClicksBlocked.url | String | The malicious URL that was clicked. | 
| Proofpoint.ClicksBlocked.userAgent | String | The User-Agent header from the clicker's HTTP request. | 


#### Command Example
```!proofpoint-get-events interval="2021-06-07T02:00:00Z/2021-06-07T03:00:00Z"```

#### Context Example
```json
{
    "Proofpoint": {
        "ClicksBlocked": null,
        "ClicksPermitted": null,
        "MessagesBlocked": [
            {
                "GUID": "9JRzwqiZEzBesdfnEM48ItsowO9ZJ1jmBbo",
                "QID": "3901vhsdfsdfg0q5d-1",
                "ccAddresses": [],
                "cluster": "hosted",
                "completelyRewritten": false,
                "fromAddress": [
                    "xxxx@xxx.com"
                ],
                "headerFrom": "\"xxxx@xxx.com\" <xxxx@xxx.com>",
                "headerReplyTo": null,
                "id": "867899c4-bbbvnvde-9948-fxv0a2-740c13aafb98",
                "impostorScore": 0,
                "malwareScore": 0,
                "messageID": "<98fd30b9-b15b-b883-ca4xcvxvc8-3a0dsfsf766719bc4@xxxx@xxx.com>",
                "messageParts": [
                    {
                        "contentType": "text/html",
                        "disposition": "inline",
                        "filename": "text.html",
                        "md5": "af671999d59182d8e66e100d4140b577",
                        "oContentType": "text/html",
                        "sandboxStatus": null,
                        "sha256": "99e2546be00c1c2a763a51861dfgf6b2981871051843dc18542ba1417b0b464c00f"
                    }
                ],
                "messageSize": 3684,
                "messageTime": "2021-06-07T01:50:00.000Z",
                "modulesRun": [
                    "av",
                    "spf",
                    "dkimv",
                    "spam",
                    "dmarc",
                    "pdr",
                    "urldefense"
                ],
                "phishScore": 100,
                "policyRoutes": [
                    "default_inbound"
                ],
                "quarantineFolder": "Phish",
                "quarantineRule": "inbound_spam_phish",
                "recipient": [
                    "xxxx@xxx.com"
                ],
                "replyToAddress": [],
                "sender": "xxxx@xxx.com",
                "senderIP": "000.000.000.000",
                "spamScore": 100,
                "subject": "Your mailbox is full......",
                "threatsInfoMap": [
                    {
                        "campaignID": null,
                        "classification": "phish",
                        "threat": "io/login/verify",
                        "threatID": "9a53601a616eb78609e525sdfsdfc0f73356c3d9ff80f00e782105ff08c53ee5a3cfca",
                        "threatStatus": "active",
                        "threatTime": "2021-06-07T00:47:12.000Z",
                        "threatType": "url",
                        "threatUrl": "https://threatinsight.proofpoint.com"
                    }
                ],
                "toAddresses": [
                    "xxxx@xxx.com"
                ],
                "xmailer": null
            }
        ],
        "MessagesDelivered": null
    }
}
```

#### Human Readable Output

>### Proofpoint Events
>|clicksBlocked|clicksPermitted|messagesBlocked|messagesDelivered|queryEndTime|
>|---|---|---|---|---|
>|  |  | {'spamScore': 100, 'phishScore': 100, 'threatsInfoMap': [{'threatID': '9a53601a616eb78609e525c0f73356c3d9ff80f00e782105ff08c53ee5a3cfca', 'threatStatus': 'active', 'classification': 'phish', 'threatUrl': 'https://threatinsight.proofpoint.com', 'threatTime': '2021-06-07T00:47:12.000Z', 'threat': 'storage.libertychurch9848737878.io/login/verify', 'campaignID': None, 'threatType': 'url'}, {'threatID': 'b72f9ac2cec86c5f2fb795ea47f2aea23d402fe46c5c64e2565363464b1b0eb2', 'threatStatus': 'active', 'classification': 'phish', 'threatUrl': 'https://threatinsight.proofpoint.com/1c863185-589c-ad2d-49cb-0020fe555aae/threat/email/b72f9ac2cec86c5f2fb795ea47f2aea23d402fe46c5c64e2565363464b1b0eb2', 'threatTime': '2021-06-07T00:47:23.000Z', 'threat': 'libertychurch9848737878.io', 'campaignID': None, 'threatType': 'url'}, {'threatID': 'da0ba8d6a9d5111900f5927eb4554e49fd30e6c5c4ad5b0c975feeb19c3bfc5b', 'threatStatus': 'active', 'classification': 'phish', 'threatUrl': 'https://threatinsight.proofpoint.com/1c863185-589c-ad2d-49cb-0020fe555aae/threat/email/da0ba8d6a9d5111900f5927eb4554e49fd30e6c5c4ad5b0c975feeb19c3bfc5b', 'threatTime': '2021-06-07T00:47:22.000Z', 'threat': 'storage.libertychurch9848737878.io/login/', 'campaignID': None, 'threatType': 'url'}], 'messageTime': '2021-06-07T01:50:00.000Z', 'impostorScore': 0.0, 'malwareScore': 0, 'cluster': 'hosted', 'subject': 'Your mailbox is full......', 'quarantineFolder': 'Phish', 'quarantineRule': 'inbound_spam_phish', 'policyRoutes': ['default_inbound'], 'modulesRun': ['av', 'spf', 'dkimv', 'spam', 'dmarc', 'pdr', 'urldefense'], 'messageSize': 3684, 'headerFrom': '"xxxx@xxx.com" <xxxx@xxx.com>', 'headerReplyTo': None, 'fromAddress': ['xxxx@xxx.com'], 'ccAddresses': [], 'replyToAddress': [], 'toAddresses': ['xxxx@xxx.com'], 'xmailer': None, 'messageParts': [{'disposition': 'inline', 'sha256': '99e2546be00c1c2a763a51861f6b29818710dsfsdf51843dc18542ba1417b0b464c00f', 'md5': 'af671999d59182d8e66e100d4140b577', 'filename': 'text.html', 'sandboxStatus': None, 'oContentType': 'text/html', 'contentType': 'text/html'}], 'completelyRewritten': False, 'id': '867899c4-bbde-9948-f0a2-740c13aafb98', 'QID': '3901vhsdvf0q5d-1', 'GUID': '9JRzwqisvsdvZEzBenEM48ItsowO9ZJ1jmBbo', 'sender': 'xxxx@xxx.com', 'recipient': ['xxxx@xxx.com'], 'senderIP': '000.000.000.000', 'messageID': '<xxxx@xxx.com>'}

### proofpoint-get-forensics
***
Returns forensics evidence.


#### Base Command

`proofpoint-get-forensics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threatId | The ID of the threat (use with either threatId or campaignId). | Optional | 
| campaignId | ID of the campaign (use with either threatId or campaignId). | Optional | 
| includeCampaignForensics | Whether to include forensic evidence for the whole campaign. Can be used with threatId only. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.Report.ID | String | The ID of the report. | 
| Proofpoint.Report.Type | String | The threat type. Can be: "attachment", "url", or "hybrid". | 
| Proofpoint.Report.Scope | String | Whether the report scope covers a campaign or an individual threat. | 
| Proofpoint.Report.Attachment.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Attachment.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Attachment.Display | String | A friendly display string. | 
| Proofpoint.Report.Attachment.SHA256 | String | The SHA256 hash of the attachment's contents. | 
| Proofpoint.Report.Attachment.MD5 | String | The MD5 hash of the attachment's contents. | 
| Proofpoint.Report.Attachment.Blacklisted | Number | Optional. Whether the file was block listed. | 
| Proofpoint.Report.Attachment.Offset | Number | Optional. The offset in bytes where the malicious content was found. | 
| Proofpoint.Report.Attachment.Size | Number | Optional. The size in bytes of the attachment's contents. | 
| Proofpoint.Report.Attachment.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.Attachment.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.Attachment.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.Cookie.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Cookie.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Cookie.Display | String | A friendly display string. | 
| Proofpoint.Report.Cookie.Action | String | Whether the cookie was set or deleted. | 
| Proofpoint.Report.Cookie.Domain | String | The domain that set the cookie. | 
| Proofpoint.Report.Cookie.Key | String | The name of the cookie being set or deleted. | 
| Proofpoint.Report.Cookie.Value | String | Optional. The content of the cookie being set. | 
| Proofpoint.Report.Cookie.Platform.Name | String | Name of the platform. | 
| Proofpoint.Report.Cookie.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.Cookie.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.DNS.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.DNS.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.DNS.Display | String | A friendly display string. | 
| Proofpoint.Report.DNS.Host | String | The hostname being resolved. | 
| Proofpoint.Report.DNS.CNames | String | Optional. An array of CNames, which were associated with the hostname. | 
| Proofpoint.Report.DNS.IP | String | Optional. An array of IP addresses that were resolved to the hostname. | 
| Proofpoint.Report.DNS.NameServers | String | Optional. The nameservers responsible for the hostname's domain. | 
| Proofpoint.Report.DNS.NameServersList | String | Optional. The nameservers responsible for the hostnames. | 
| Proofpoint.Report.DNS.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.DNS.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.DNS.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.Dropper.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Dropper.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Dropper.Display | String | A friendly display string. | 
| Proofpoint.Report.Dropper.Path | String | The location of the dropper file. | 
| Proofpoint.Report.Dropper.URL | String | Optional. The name of the static rule inside the sandbox that identified the dropper. | 
| Proofpoint.Report.Dropper.Rule | String | Optional. The URL the dropper contacted. | 
| Proofpoint.Report.Dropper.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.Dropper.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.Dropper.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.File.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.File.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.File.Display | String | A friendly display string. | 
| Proofpoint.Report.File.Path | String | Optional. The location of the file operated on. | 
| Proofpoint.Report.File.Action | String | Optional. The filesystem call made \(create, modify, or delete\). | 
| Proofpoint.Report.File.Rule | String | Optional. The name of the static rule inside the sandbox that identified the suspicious file. | 
| Proofpoint.Report.File.SHA256 | Unknown | Optional. The SH256 hash of the file's contents. | 
| Proofpoint.Report.File.MD5 | String | Optional. The MD5 hash of the file's contents. | 
| Proofpoint.Report.File.Size | Number | Optional. The size in bytes of the file's contents. | 
| Proofpoint.Report.File.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.File.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.File.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.IDS.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.IDS.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.IDS.Display | String | A friendly display string. | 
| Proofpoint.Report.IDS.Name | String | The friendly name of the IDS rule that observed the malicious traffic. | 
| Proofpoint.Report.IDS.SignatureID | String | The identifier of the IDS rule that observed the malicious traffic. | 
| Proofpoint.Report.IDS.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.IDS.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.IDS.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.Mutex.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Mutex.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Mutex.Display | String | A friendly display string. | 
| Proofpoint.Report.Mutex.Name | String | The name of the mutex. | 
| Proofpoint.Report.Mutex.Path | String | Optional. The path to the process which spawned the mutex. | 
| Proofpoint.Report.Mutex.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.Mutex.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.Mutex.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.Network.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Network.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Network.Display | String | A friendly display string. | 
| Proofpoint.Report.Network.Action | String | The type of network activity being initiated \(connect or listen\). | 
| Proofpoint.Report.Network.IP | String | The remote IP address being contacted. | 
| Proofpoint.Report.Network.Port | String | The remote IP port being contacted. | 
| Proofpoint.Report.Network.Type | String | The protocol being used \(tcp or udp\). | 
| Proofpoint.Report.Network.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.Network.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.Network.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.Process.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Process.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Process.Display | String | A friendly display string. | 
| Proofpoint.Report.Process.Action | String | The action performed on the process. Relevant when create is produced. | 
| Proofpoint.Report.Process.Path | String | The location of the executable that spawned the process. | 
| Proofpoint.Report.Process.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.Process.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.Process.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.Registry.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Registry.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Registry.Display | String | A friendly display string. | 
| Proofpoint.Report.Registry.Name | String | Optional. The name of the registry entry being created or set. | 
| Proofpoint.Report.Registry.Action | String | The registry change made \(create or set\). | 
| Proofpoint.Report.Registry.Key | String | The location of the registry key being modified. | 
| Proofpoint.Report.Registry.Value | String | Optional. The contents of the key being created or set. | 
| Proofpoint.Report.Registry.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.Registry.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.Registry.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.URL.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.URL.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.URL.Display | String | A friendly display string. | 
| Proofpoint.Report.URL.URL | String | The URL which was observed. | 
| Proofpoint.Report.URL.Blacklisted | Boolean | Optional. Whether the URL appeared on a block list. | 
| Proofpoint.Report.URL.SHA256 | String | Optional. The SHA256 hash of the file downloaded from the URL. | 
| Proofpoint.Report.URL.MD5 | String | Optional. The MD5 hash of the file downloaded from the URL. | 
| Proofpoint.Report.URL.Size | Number | Optional. The size in bytes of the file retrieved from the URL. | 
| Proofpoint.Report.URL.HTTPStatus | Number | Optional. The HTTP status code that was produced when our sandbox visited the URL. | 
| Proofpoint.Report.URL.IP | String | Optional. The IP address that was resolved to the hostname by the sandbox. | 
| Proofpoint.Report.URL.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.URL.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.URL.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.Behavior.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Behavior.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Behavior.Display | String | A friendly display string. | 
| Proofpoint.Report.Behavior.URL | String | The URL that was observed. | 
| Proofpoint.Report.Behavior.Path | String | The location of the executable which spawned the behavior. | 
| Proofpoint.Report.Behavior.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.Behavior.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.Behavior.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.Behavior.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Behavior.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Behavior.Display | String | A friendly display string. | 
| Proofpoint.Report.Behavior.URL | String | The URL that was observed. | 
| Proofpoint.Report.Behavior.Path | String | The location of the executable that spawned the behavior. | 
| Proofpoint.Report.Behavior.Platform.Name | String | The name of the platform. | 
| Proofpoint.Report.Behavior.Platform.OS | String | The operating system of the platform. | 
| Proofpoint.Report.Behavior.Platform.Version | String | The version of the platform. | 
| Proofpoint.Report.Screenshot.Time | Date | The relative time at which the evidence was observed during sandboxing. | 
| Proofpoint.Report.Screenshot.Malicious | String | Whether the evidence was used to reach a malicious verdict. | 
| Proofpoint.Report.Screenshot.Display | String | A friendly display string. | 
| Proofpoint.Report.Screenshot.URL | String | The URL hosting the screenshot image. | 


#### Command Example
```!proofpoint-get-forensics campaignId="35e291e1-c9da-4ebd-b229-538bf759b546"```

#### Context Example
```json
{
    "Proofpoint": {
        "Report": {
            "Attachment": [
                {
                    "Display": "Malicious attachment with SHA-256: 1c207a1ea4b89cc63c2d8391afcf25",
                    "Malicious": true,
                    "Platform": [
                        {
                            "Name": "Win10",
                            "OS": "win",
                            "Version": "win10"
                        }
                    ],
                    "SHA256": "1c207da4b89cc63c2d8391afcf25",
                    "Time": 0
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Forensic results from ProofPoint for ID: 35e291e1-c9da-4ebd-b229-538bf759b546
>|ID|Scope|Type|
>|---|---|---|
>| 35e291e1-c9da-4ebd-b229-538bf759b546 | CAMPAIGN |  |


### proofpoint-get-events-clicks-blocked
***
Gets events for clicks to malicious URLs blocked in the specified time period. Must provide either the interval or time_range arguments.


#### Base Command

`proofpoint-get-events-clicks-blocked`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_status | Click's threat status to be retrieved. If no value is specified, active and cleared threats will be retrieved. Possible values: 'active', 'cleared', and 'falsePositive'. Possible values are: active, cleared, falsePositive. | Optional | 
| interval | ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one hour. For example: 2021-04-27T09:00:00Z/2021-04-27T10:00:00Z. | Optional | 
| time_range | Represents the start of the data retrieval period. For example: 1 week, 2 days, 3 hours, etc. The maximum is 1 week. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.ClicksBlocked.url | String | The malicious URL was clicked. | 
| Proofpoint.ClicksBlocked.classification | String | The threat category of the malicious URL \(Malware, Phish, or Spam\) | 
| Proofpoint.ClicksBlocked.clickTime | Date | The time the user clicked the URL. | 
| Proofpoint.ClicksBlocked.threatTime | Date | The time that Proofpoint identified the URL as a threat. | 
| Proofpoint.ClicksBlocked.userAgent | String | The User-Agent header from the clicker's HTTP request. | 
| Proofpoint.ClicksBlocked.campaignId | String | An identifier for the campaign of which the threat is a member. | 
| Proofpoint.ClicksBlocked.id | String | The unique ID of the click. | 
| Proofpoint.ClicksBlocked.clickIP | String | The external IP address of the user who clicked the link. | 
| Proofpoint.ClicksBlocked.sender | String | The email address of the sender. The user-part is hashed. The domain-part is cleartext. | 
| Proofpoint.ClicksBlocked.recipient | String | The email address of the recipient. | 
| Proofpoint.ClicksBlocked.senderIP | String | The IP address of the sender. | 
| Proofpoint.ClicksBlocked.threatID | String | The unique identifier associated with this threat. | 
| Proofpoint.ClicksBlocked.threatURL | String | A link to the entry on the TAP dashboard for the particular threat. | 
| Proofpoint.ClicksBlocked.threatStatus | String | The current state of the threat. | 
| Proofpoint.ClicksBlocked.messageID | String | The ID of the message that the URL belongs to. | 
| Proofpoint.ClicksBlocked.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS. | 


#### Command Example
```!proofpoint-get-events-clicks-blocked time_range="1 hour"```

#### Context Example
```json
{
    "Proofpoint": {
        "ClicksBlocked": {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "clickIP": "192.0.2.2",
            "clickTime": "2010-01-22T00:00:10.000Z",
            "messageID": "4444",
            "recipient": "xxxx@xxx.com",
            "sender": "xxxx@xxx.com",
            "senderIP": "000.000.000.000",
            "threatID": "threat_num2",
            "threatTime": "2010-01-22T00:00:20.000Z",
            "threatURL": "https://threatinsight.proofpoint.com",
            "url": "http://badguy.zz/",
            "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0"
        }
    }
}
```

#### Human Readable Output

>### Blocked Clicks
>|Id|Sender IP|Recipient|Classification|Threat ID|Threat URL|Threat Status|Threat Time|Click Time|Campaign Id|User Agent|
>|---|---|---|---|---|---|---|---|---|---|---|
>|  | 000.000.000.000 | xxxx@xxx.com | MALWARE | threat_num2 | https://threatinsight.proofpoint.com |  | 2010-01-22T00:00:20.000Z | 2010-01-22T00:00:10.000Z | 46e01b8a-c899-404d-bcd9-189bb393d1a7 | Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0 |


### proofpoint-get-events-clicks-permitted
***
Get events for clicks to malicious URLs permitted in the specified time period.  Must provide either the interval or time_range arguments.


#### Base Command

`proofpoint-get-events-clicks-permitted`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_status | Click's threat status to be retrieved. If no value is specified, active and cleared threats will be retrieved. Possible values: 'active', 'cleared', and 'falsePositive'. Possible values are: active, cleared, falsePositive. | Optional | 
| interval | ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one hour. For example: 2021-04-27T09:00:00Z/2021-04-27T10:00:00Z. | Optional | 
| time_range | Represents the start of the data retrieval period. For example: 1 week, 2 days, 3 hours, etc. The maximum is 1 week. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.ClicksPermitted.url | String | The malicious URL that was clicked. | 
| Proofpoint.ClicksPermitted.classification | String | The threat category of the malicious URL \(Malware, Phish, or Spam\). | 
| Proofpoint.ClicksPermitted.clickTime | Date | The time the user clicked the URL. | 
| Proofpoint.ClicksPermitted.threatTime | Date | The time that Proofpoint identified the URL as a threat. | 
| Proofpoint.ClicksPermitted.userAgent | String | The User-Agent header from the clicker's HTTP request. | 
| Proofpoint.ClicksPermitted.campaignId | String | An identifier for the campaign of which the threat is a member. | 
| Proofpoint.ClicksPermitted.id | String | The unique ID of the click. | 
| Proofpoint.ClicksPermitted.clickIP | String | The external IP address of the user who clicked the link. | 
| Proofpoint.ClicksPermitted.sender | String | The email address of the sender. The user-part is hashed. The domain-part is in cleartext. | 
| Proofpoint.ClicksPermitted.recipient | String | The email address of the recipient. | 
| Proofpoint.ClicksPermitted.senderIP | String | The IP address of the sender. | 
| Proofpoint.ClicksPermitted.threatID | String | The unique identifier associated with this threat. | 
| Proofpoint.ClicksPermitted.threatURL | String | A link to the entry on the TAP dashboard for the particular threat. | 
| Proofpoint.ClicksPermitted.threatStatus | String | The current state of the threat. | 
| Proofpoint.ClicksPermitted.messageID | String | The ID of the message that the URL belongs to. | 
| Proofpoint.ClicksPermitted.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS. | 


#### Command Example
```!proofpoint-get-events-clicks-permitted time_range="1 hour"```

#### Context Example
```json
{
    "Proofpoint": {
        "ClicksPermitted": {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "clickIP": "192.0.2.2",
            "clickTime": "2010-01-22T00:00:10.000Z",
            "messageID": "4444",
            "recipient": "xxxx@xxx.com",
            "sender": "9facbf452def2d7efc5b5c48cdb837fa@badguy.zz",
            "senderIP": "000.000.000.000",
            "threatID": "threat_num2",
            "threatTime": "2010-01-22T00:00:20.000Z",
            "threatURL": "https://threatinsight.proofpoint.com",
            "url": "http://badguy.zz/",
            "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0"
        }
    }
}
```

#### Human Readable Output

>### Permitted Clicks
>|Id|Sender IP|Recipient|Classification|Threat ID|Threat URL|Threat Status|Threat Time|Click Time|Campaign Id|User Agent|
>|---|---|---|---|---|---|---|---|---|---|---|
>|  | 192.0.2.255 | xxxx@xxx.com| MALWARE | threat_num2 | https://threatinsight.proofpoint.com |  | 2010-01-22T00:00:20.000Z | 2010-01-22T00:00:10.000Z | 46e01b8a-c899-404d-bcd9-189bb393d1a7 | Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0 |


### proofpoint-get-events-messages-blocked
***
Get events for blocked messages in the specified time period. Must provide either the interval or time_range arguments.


#### Base Command

`proofpoint-get-events-messages-blocked`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_type | Message's threat type to be retrieved. If no value is specified, all threat types will be retrieved. Possible values: 'url', 'attachment', and 'message'. Possible values are: url, attachment, message. | Optional | 
| threat_status | Message's threat status to be retrieved. If no value is specified, active and cleared threats will be retrieved. Possible values: 'active', 'cleared', and 'falsePositive'. Possible values are: active, cleared, falsePositive. | Optional | 
| interval | ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one hour. For example: 2021-04-27T09:00:00Z/2021-04-27T10:00:00Z. | Optional | 
| time_range | Represents the start of the data retrieval period. For example: 1 week, 2 days, 3 hours, etc. The maximum is 1 week. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.MessagesBlocked.spamScore | Number | The spam score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesBlocked.phishScore | Number | The phish score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesBlocked.threatsInfoMap | List | List that contains details about detected threats within the message. Contains: campaignID, classification, threat, threatID, threatStatus,threatTime, threatType, threatUrl. | 
| Proofpoint.MessagesBlocked.messageTime | Date | The time the message was delivered to the user or quarantined by PPS. | 
| Proofpoint.MessagesBlocked.impostorScore | Number | The impostor score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesBlocked.malwareScore | Number | The malware score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesBlocked.cluster | String | The name of the PPS cluster that processed the message. | 
| Proofpoint.MessagesBlocked.subject | String | The subject line of the message, if available. | 
| Proofpoint.MessagesBlocked.quarantineFolder | String | The name of the folder that contains the quarantined message. This appears only for blocked messages. For delivered messages will be 'None'. | 
| Proofpoint.MessagesBlocked.quarantineRule | String | The name of the rule that quarantined the message. This appears only for messagesBlocked events. | 
| Proofpoint.MessagesBlocked.policyRoutes | List | The policy routes that the message matched during processing by PPS. | 
| Proofpoint.MessagesBlocked.modulesRun | String | The list of PPS modules that processed the message. | 
| Proofpoint.MessagesBlocked.messageSize | Number | The size in bytes of the message, including headers and attachments. | 
| Proofpoint.MessagesBlocked.Header.headerFrom | String | The full content of the From header, including any friendly name. | 
| Proofpoint.MessagesBlocked.Header.headerReplyTo | String | If present, the full content of the Reply-To: header, including any friendly names. | 
| Proofpoint.MessagesBlocked.Header.fromAddress | List | The email address contained in the From header, excluding the friendly name. | 
| Proofpoint.MessagesBlocked.Header.ccAddresses | List | A list of email addresses contained within the CC: header, excluding friendly names. | 
| Proofpoint.MessagesBlocked.Header.replyToAddress | List | The email address contained in the Reply-To: header, excluding friendly name. | 
| Proofpoint.MessagesBlocked.Header.toAddresses | List | A list of email addresses contained within the To: header, excluding friendly names. | 
| Proofpoint.MessagesBlocked.Header.xmailer | String | The content of the X-Mailer: header, if present. | 
| Proofpoint.MessagesBlocked.messageParts | List | An array of structures that contain details about parts of the message, including both message bodies and attachments. | 
| Proofpoint.MessagesBlocked.completelyRewritten | String | The rewrite status of the message. If value is true, all instances of URL threats within the message were successfully rewritten. If the value is false, at least one instance of the threat URL was not rewritten. If the value is 'na', the message did not contain any URL-based threats. | 
| Proofpoint.MessagesBlocked.id | String | The unique ID of the message. | 
| Proofpoint.MessagesBlocked.sender | String | The email address of the SMTP \(envelope\) sender. The user-part is hashed. The domain-part is cleartext. | 
| Proofpoint.MessagesBlocked.recipient | List | A list containing the email addresses of the recipients. | 
| Proofpoint.MessagesBlocked.senderIP | String | The IP address of the sender. | 
| Proofpoint.MessagesBlocked.messageID | String | Message-ID extracted from the headers of the email message. | 
| Proofpoint.MessagesBlocked.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS. | 


#### Command Example
```!proofpoint-get-events-messages-blocked interval="2021-06-07T02:00:00Z/2021-06-07T03:00:00Z"```

#### Context Example
```json
{
    "Proofpoint": {
        "MessagesBlocked": [
            {
                "GUID": "9JRzwqiZEzBenEMsdgsdfg48ItsowO9ZJ1jmBbo",
                "Header": {
                    "ccAddresses": [],
                    "fromAddress": [
                        "xxxx@xxx.com"
                    ],
                    "headerFrom": "\"xxxx@xxx.com\" <xxxx@xxx.com>",
                    "headerReplyTo": null,
                    "replyToAddress": [],
                    "toAddresses": [
                        "xxxx@xxx.com"
                    ],
                    "xmailer": null
                },
                "cluster": "hosted",
                "completelyRewritten": false,
                "id": "867899c4-bbde-9948-f0a2-740c13aafb98",
                "impostorScore": 0,
                "malwareScore": 0,
                "messageID": "<xxxx@xxx.com>",
                "messageParts": [
                    {
                        "contentType": "text/html",
                        "disposition": "inline",
                        "filename": "text.html",
                        "md5": "a",
                        "oContentType": "text/html",
                        "sandboxStatus": null,
                        "sha256": "99843dc18542ba1417b0b464c00f"
                    }
                ],
                "messageSize": 3684,
                "messageTime": "2021-06-07T01:50:00.000Z",
                "modulesRun": [
                    "av",
                    "spf",
                    "dkimv",
                    "spam",
                    "dmarc",
                    "pdr",
                    "urldefense"
                ],
                "phishScore": 100,
                "policyRoutes": [
                    "default_inbound"
                ],
                "quarantineFolder": "Phish",
                "quarantineRule": "inbound_spam_phish",
                "recipient": [
                    "xxxx@xxx.com"
                ],
                "sender": "xxxx@xxx.com",
                "senderIP": "000.000.000.000",
                "spamScore": 100,
                "subject": "Your mailbox is full......",
                "threatsInfoMap": [
                    {
                        "campaignID": null,
                        "classification": "phish",
                        "threat": "login/verify",
                        "threatID": "9a",
                        "threatStatus": "active",
                        "threatTime": "2021-06-07T00:47:12.000Z",
                        "threatType": "url",
                        "threatUrl": "https://threatinsight.proofpoint.com"
                    },
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Blocked Messages
>|Sender IP|Sender|Recipient|Subject|Message Size|Message Time|Malware Score|Phish Score|Spam Score|
>|---|---|---|---|---|---|---|---|---|
>| 000.000.000.000 | xxxx@xxx.com | xxxx@xxx.com | Your mailbox is full...... | 3684 | 2021-06-07T01:50:00.000Z | 0 | 100 | 100 |
>### Blocked Messages Threats Information
>|Sender|Recipient|Subject|Classification|Threat|Threat Status|Threat Url|Threat ID|Threat Time|Campaign ID|
>|---|---|---|---|---|---|---|---|---|---|
>| xxxx@xxx.com | xxxx@xxx.com | Your mailbox is full...... | phish | login/verify | active | https://threatinsight.proofpoint.com | 9a53601a616eb78609e525c0f3ee5a3cfca | 2021-06-07T00:47:12.000Z |  |


### proofpoint-get-events-messages-delivered
***
Get events for delivered messages in the specified time period. Must provide either the interval or time_range arguments.


#### Base Command

`proofpoint-get-events-messages-delivered`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_type | Message's threat type to be retrieved. If no value is specified, all threat types will be retrieved. Possible values: 'url', 'attachment', and 'message'. Possible values are: url, attachment, message. | Optional | 
| threat_status | Message's threat status to be retrieved. If no value is specified, active and cleared threats will be retrieved. Possible values: 'active', 'cleared', and 'falsePositive'. Possible values are: active, cleared, falsePositive. | Optional | 
| interval | ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one hour. For example: 2021-04-27T09:00:00Z/2021-04-27T10:00:00Z. | Optional | 
| time_range | Represents the start of the data retrieval period. For example: 1 week, 2 days, 3 hours, etc. The maximum is 1 week. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.MessagesDelivered.spamScore | Number | The spam score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.phishScore | Number | The phish score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.threatsInfoMap | List | List that contains details about detected threats within the message. Contains: campaignID, classification, threat, threatID, threatStatus,threatTime, threatType, threatUrl. | 
| Proofpoint.MessagesDelivered.messageTime | Date | The time the message was delivered to the user or quarantined by PPS. | 
| Proofpoint.MessagesDelivered.impostorScore | Number | The impostor score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.malwareScore | Number | The malware score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.cluster | String | The name of the PPS cluster that processed the message. | 
| Proofpoint.MessagesDelivered.subject | String | The subject line of the message, if available. | 
| Proofpoint.MessagesDelivered.quarantineFolder | String | The name of the folder that contains the quarantined message. This appears only for blocked messages. For delivered messages will be 'None'. | 
| Proofpoint.MessagesDelivered.quarantineRule | String | The name of the rule that quarantined the message. This appears only for messagesBlocked events. | 
| Proofpoint.MessagesDelivered.policyRoutes | List | The policy routes that the message matched during processing by PPS. | 
| Proofpoint.MessagesDelivered.modulesRun | String | The list of PPS modules that processed the message. | 
| Proofpoint.MessagesDelivered.messageSize | Number | The size in bytes of the message, including headers and attachments. | 
| Proofpoint.MessagesDelivered.Header.headerFrom | String | The full content of the From header, including any friendly name. | 
| Proofpoint.MessagesDelivered.Header.headerReplyTo | String | If present, the full content of the Reply-To: header, including any friendly names. | 
| Proofpoint.MessagesDelivered.Header.fromAddress | List | The email address contained in the From header, excluding the friendly name. | 
| Proofpoint.MessagesDelivered.Header.ccAddresses | List | A list of email addresses contained within the CC: header, excluding friendly names. | 
| Proofpoint.MessagesDelivered.Header.replyToAddress | List | The email address contained in the Reply-To: header, excluding friendly name. | 
| Proofpoint.MessagesDelivered.Header.toAddresses | List | A list of email addresses contained within the To: header, excluding friendly names. | 
| Proofpoint.MessagesDelivered.Header.xmailer | String | The content of the X-Mailer: header, if present. | 
| Proofpoint.MessagesDelivered.messageParts | List | An array of structures that contains details about parts of the message, including both message bodies and attachments. | 
| Proofpoint.MessagesDelivered.completelyRewritten | String | The rewrite status of the message. If value is true, all instances of URL threats within the message were successfully rewritten. If the value is false, at least one instance of the threat URL was not rewritten. If the value is 'na', the message did not contain any URL-based threats. | 
| Proofpoint.MessagesDelivered.id | String | The unique ID of the message. | 
| Proofpoint.MessagesDelivered.sender | String | The email address of the SMTP \(envelope\) sender. The user-part is hashed. The domain-part is cleartext. | 
| Proofpoint.MessagesDelivered.recipient | List | A list containing the email addresses of the recipients. | 
| Proofpoint.MessagesDelivered.senderIP | String | The IP address of the sender. | 
| Proofpoint.MessagesDelivered.messageID | String | Message-ID extracted from the headers of the email message. | 
| Proofpoint.MessagesDelivered.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique. | 


#### Command Example
```!proofpoint-get-events-messages-delivered interval="2021-06-03T17:00:00Z/2021-06-03T18:00:00Z"```

#### Context Example
```json
{
    "Proofpoint": {
        "MessagesDelivered": {
            "GUID": "Ggfsdfsdf",
            "Header": {
                "ccAddresses": [],
                "fromAddress": [
                    "xxxx@xxx.com"
                ],
                "headerFrom": "\"j.\" <xxxx@xxx.com>",
                "headerReplyTo": null,
                "replyToAddress": [],
                "toAddresses": [],
                "xmailer": null
            },
            "cluster": "hosted",
            "completelyRewritten": true,
            "id": "1828003vsdv05566e842",
            "impostorScore": 0,
            "malwareScore": 0,
            "messageID": "<SI2PR0dfbvd.xxxx@xxx.com.com>",
            "messageParts": [
                {
                    "contentType": "text/html",
                    "disposition": "inline",
                    "filename": "text.html",
                    "md5": "fcfa9b21f43fbdf02965263c63e",
                    "oContentType": "text/html",
                    "sandboxStatus": null,
                    "sha256": "72d3dc7a01dfbdbe8e871536864f56bf235ba08ff259105ac"
                },
            ],
            "messageSize": 10171,
            "messageTime": "2021-06-02T13:41:32.000Z",
            "modulesRun": [
                "av",
                "spf",
                "dkimv",
                "spam",
                "dmarc",
                "urldefense"
            ],
            "phishScore": 0,
            "policyRoutes": [
                "default_inbound",
                "allow_relay"
            ],
            "quarantineFolder": null,
            "quarantineRule": null,
            "recipient": [
                "xxxx@xxx.com"
            ],
            "sender": "xxxx@xxx.com",
            "senderIP": "400.000.000",
            "spamScore": 43,
            "subject": "=",
            "threatsInfoMap": [
                {
                    "campaignID": null,
                    "classification": "phish",
                    "threat": "https://bit.ly",
                    "threatID": "45fe3b35ghkk2b8916934b6c0a536cc9b2603d03",
                    "threatStatus": "active",
                    "threatTime": "2021-06-03T07:17:11.000Z",
                    "threatType": "url",
                    "threatUrl": "https://threatinsight.proofpoint.com"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Delivered Messages
>|Sender IP|Sender|Recipient|Subject|Message Size|Message Time|Malware Score|Phish Score|Spam Score|
>|---|---|---|---|---|---|---|---|---|
>| 00.000.000.0000 | xxxx@xxx.com | xxxx@xxx.com | = | 10171 | 2021-06-02T13:41:32.000Z | 0 | 0 | 43 |
>
>### Delivered Messages Threats Information
>|Sender|Recipient|Subject|Classification|Threat|Threat Status|Threat Url|Threat ID|Threat Time|Campaign ID|
>|---|---|---|---|---|---|---|---|---|---|
>| xxxx@xxx.com | xxxx@xxx.com | = | phish | https://bit.ly | active | https://threatinsight.proofpoint.com| 45fe3b35b7bd2adfad6dea4d305bea3e7c1a2b8gfhh03d03 | 2021-06-03T07:17:11.000Z |  |


### proofpoint-list-issues
***
Get events for clicks to malicious URLs permitted and messages delivered containing a known attachment threat within the specified time period. Must provide either the interval or time_range arguments.


#### Base Command

`proofpoint-list-issues`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_type | Event's threat type to be retrieved. If no value is specified, all threat types will be retrieved. Possible values: 'url', 'attachment', and 'message'. Possible values are: url, attachment, message. | Optional | 
| threat_status | Event's threat status to be retrieved.If no value is specified, active and cleared threats will be retrieved. Possible values: 'url', 'attachment', and 'message'. Possible values are: active, cleared, falsePositive. | Optional | 
| interval | ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one hour. For example: 2021-04-27T09:00:00Z/2021-04-27T10:00:00Z. | Optional | 
| time_range | Represents the start of the data retrieval period. For example: 1 week, 2 days, 3 hours, etc. The maximum is 1 week. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.ClicksPermitted.url | String | The malicious URL was clicked. | 
| Proofpoint.ClicksPermitted.classification | String | The threat category of the malicious URL \(Malware, Phish, or Spam\). | 
| Proofpoint.ClicksPermitted.clickTime | Date | The time the user clicked the URL. | 
| Proofpoint.ClicksPermitted.threatTime | Date | The time that Proofpoint identified the URL as a threat. | 
| Proofpoint.ClicksPermitted.userAgent | String | The User-Agent header from the clicker's HTTP request. | 
| Proofpoint.ClicksPermitted.campaignId | String | An identifier for the campaign of which the threat is a member. | 
| Proofpoint.ClicksPermitted.id | String | The unique ID of the click. | 
| Proofpoint.ClicksPermitted.clickIP | String | The external IP address of the user who clicked the link. | 
| Proofpoint.ClicksPermitted.sender | String | The email address of the sender. The user-part is hashed. The domain-part is in cleartext. | 
| Proofpoint.ClicksPermitted.recipient | String | The email address of the recipient. | 
| Proofpoint.ClicksPermitted.senderIP | String | The IP address of the sender. | 
| Proofpoint.ClicksPermitted.threatID | String | The unique identifier associated with this threat. | 
| Proofpoint.ClicksPermitted.threatURL | String | A link to the entry on the TAP dashboard for the particular threat. | 
| Proofpoint.ClicksPermitted.threatStatus | String | The current state of the threat. | 
| Proofpoint.ClicksPermitted.messageID | String | The ID of the message that the URL belongs to. | 
| Proofpoint.ClicksPermitted.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique. | 
| Proofpoint.MessagesDelivered.spamScore | Number | The spam score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.phishScore | Number | The phish score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.threatsInfoMap | List | List which contain details about detected threats within the message. Contains: campaignID, classification, threat, threatID, threatStatus,threatTime, threatType, threatUrl. | 
| Proofpoint.MessagesDelivered.messageTime | Date | THe time the message was delivered to the user or quarantined by PPS. | 
| Proofpoint.MessagesDelivered.impostorScore | Number | The impostor score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.malwareScore | Number | The malware score of the message. Higher scores indicate higher certainty. | 
| Proofpoint.MessagesDelivered.cluster | String | The name of the PPS cluster that processed the message. | 
| Proofpoint.MessagesDelivered.subject | String | The subject line of the message, if available. | 
| Proofpoint.MessagesDelivered.quarantineFolder | String | The name of the folder that contains the quarantined message. This appears only for blocked messages. For delivered messages will be 'None'. | 
| Proofpoint.MessagesDelivered.quarantineRule | String | The name of the rule that quarantined the message. This appears only for messagesBlocked events. | 
| Proofpoint.MessagesDelivered.policyRoutes | List | The policy routes that the message matched during processing by PPS. | 
| Proofpoint.MessagesDelivered.modulesRun | String | The list of PPS modules that processed the message. | 
| Proofpoint.MessagesDelivered.messageSize | Number | The size in bytes of the message, including headers and attachments. | 
| Proofpoint.MessagesDelivered.Header.headerFrom | String | The full content of the From header, including any friendly name. | 
| Proofpoint.MessagesDelivered.Header.headerReplyTo | String | If present, the full content of the Reply-To: header, including any friendly names. | 
| Proofpoint.MessagesDelivered.Header.fromAddress | List | The email address contained in the From header, excluding any friendly name. | 
| Proofpoint.MessagesDelivered.Header.ccAddresses | List | A list of email addresses contained within the CC: header, excluding any friendly names. | 
| Proofpoint.MessagesDelivered.Header.replyToAddress | List | The email address contained in the Reply-To: header, excluding any friendly name. | 
| Proofpoint.MessagesDelivered.Header.toAddresses | List | A list of email addresses contained within the To: header, excluding any friendly names. | 
| Proofpoint.MessagesDelivered.Header.xmailer | String | The content of the X-Mailer: header, if present. | 
| Proofpoint.MessagesDelivered.messageParts | List | An array of structures that contain details about parts of the message, including both message bodies and attachments. | 
| Proofpoint.MessagesDelivered.completelyRewritten | String | The rewrite status of the message. If value is true, all instances of URL threats within the message were successfully rewritten. If the value is false, at least one instance of the threat URL was not rewritten. If the value is 'na', the message did not contain any URL-based threats. | 
| Proofpoint.MessagesDelivered.id | String | The unique ID of the message. | 
| Proofpoint.MessagesDelivered.sender | String | The email address of the SMTP \(envelope\) sender. The user-part is hashed. The domain-part is cleartext. | 
| Proofpoint.MessagesDelivered.recipient | List | A list containing the email addresses of the recipients | 
| Proofpoint.MessagesDelivered.senderIP | String | The IP address of the sender. | 
| Proofpoint.MessagesDelivered.messageID | String | Message-ID extracted from the headers of the email message. | 
| Proofpoint.MessagesDelivered.GUID | String | The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique. | 


#### Command Example
```!proofpoint-list-issues interval="2021-06-03T17:00:00Z/2021-06-03T18:00:00Z"```

#### Context Example
```json
{
    "Proofpoint": {
        "MessagesDelivered": {
            "GUID": "Ggfsdfsdf",
            "Header": {
                "ccAddresses": [],
                "fromAddress": [
                    "xxxx@xxx.com"
                ],
                "headerFrom": "\"j.\" <xxxx@xxx.com>",
                "headerReplyTo": null,
                "replyToAddress": [],
                "toAddresses": [],
                "xmailer": null
            },
            "cluster": "hosted",
            "completelyRewritten": true,
            "id": "1828003vsdv05566e842",
            "impostorScore": 0,
            "malwareScore": 0,
            "messageID": "<SI2PR0dfbvd.xxxx@xxx.com.com>",
            "messageParts": [
                {
                    "contentType": "text/html",
                    "disposition": "inline",
                    "filename": "text.html",
                    "md5": "fcfa9b21f43fbdf02965263c63e",
                    "oContentType": "text/html",
                    "sandboxStatus": null,
                    "sha256": "72d3dc7a01dfbdbe8e871536864f56bf235ba08ff259105ac"
                },
            ],
            "messageSize": 10171,
            "messageTime": "2021-06-02T13:41:32.000Z",
            "modulesRun": [
                "av",
                "spf",
                "dkimv",
                "spam",
                "dmarc",
                "urldefense"
            ],
            "phishScore": 0,
            "policyRoutes": [
                "default_inbound",
                "allow_relay"
            ],
            "quarantineFolder": null,
            "quarantineRule": null,
            "recipient": [
                "xxxx@xxx.com"
            ],
            "sender": "xxxx@xxx.com",
            "senderIP": "400.000.000",
            "spamScore": 43,
            "subject": "=",
            "threatsInfoMap": [
                {
                    "campaignID": null,
                    "classification": "phish",
                    "threat": "https://bit.ly",
                    "threatID": "45fe3b35ghkk2b8916934b6c0a536cc9b2603d03",
                    "threatStatus": "active",
                    "threatTime": "2021-06-03T07:17:11.000Z",
                    "threatType": "url",
                    "threatUrl": "https://threatinsight.proofpoint.com"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Delivered Messages
>|Sender IP|Sender|Recipient|Subject|Message Size|Message Time|Malware Score|Phish Score|Spam Score|
>|---|---|---|---|---|---|---|---|---|
>| 00.000.000.0000 | xxxx@xxx.com | xxxx@xxx.com | = | 10171 | 2021-06-02T13:41:32.000Z | 0 | 0 | 43 |
>
>### Delivered Messages Threats Information
>|Sender|Recipient|Subject|Classification|Threat|Threat Status|Threat Url|Threat ID|Threat Time|Campaign ID|
>|---|---|---|---|---|---|---|---|---|---|
>| xxxx@xxx.com | xxxx@xxx.com | = | phish | https://bit.ly | active | https://threatinsight.proofpoint.com| 45fe3b35b7bd2adfad6dea4d305bea3e7c1a2b8gfhh03d03 | 2021-06-03T07:17:11.000Z |  |


>### Permitted click from list-issues command result:
>**No entries.**


### proofpoint-list-campaigns
***
Gets a list of IDs of campaigns active in a specified time period. Must provide either the interval or time_range arguments.


#### Base Command

`proofpoint-list-campaigns`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval | ISO8601-formatted interval date. The minimum interval is thirty seconds. The maximum interval is one day. For example: 2021-04-27T09:00:00Z/2021-04-27T10:00:00Z. | Optional | 
| limit | The maximum number of campaign IDs to produce in the response. Defaults to 100 and the maximum supported value is 200. Default is 100. | Optional | 
| page | The page of results to return, in multiples of the specified size. Default is 1. | Optional | 
| time_range | Represents the start of the data retrieval period. For example: 1 week, 2 days, 3 hours, etc. The maximum is 1 week. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.Campaigns.id | String | The campaign ID. | 
| Proofpoint.Campaigns.lastUpdatedAt | String | Last updated timestamp of the campaign. | 


#### Command Example
```!proofpoint-list-campaigns interval="2021-06-01T11:00:00Z/2021-06-02T11:00:00Z"```

#### Context Example
```json
{
    "Proofpoint": {
        "Campaign": {
            "id": "7c91b71fdgdfgdfg591a1ad38",
            "lastUpdatedAt": "2021-06-03T13:01:57.000Z"
        }
    }
}
```

#### Human Readable Output

>### Campaigns List
>|Id|Last Updated At|
>|---|---|
>| 7c91b71fdgdfgdfg591a1ad38 | 2021-06-03T13:01:57.000Z |


### proofpoint-get-campaign
***
Gets details for a given campaign.


#### Base Command

`proofpoint-get-campaign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| campaign_id | ID of the required campaign. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.Campaign.info | List | The campaign information - ID,name, description, startDate, and notable. | 
| Proofpoint.Campaign.actors | List | A list of actor objects. | 
| Proofpoint.Campaign.families | List | A list of family objects. | 
| Proofpoint.Campaign.malware | List | A list of malware objects. | 
| Proofpoint.Campaign.techniques | List | A list of technique objects. | 
| Proofpoint.Campaign.brands | List | A list of brand objects. | 
| Proofpoint.Campaign.campaignMembers | List | A list of campaign member objects. | 


#### Command Example
```!proofpoint-get-campaign campaign_id="f3ff0874-85ef-475e-b3fe-d05f97b2ed3f"```

#### Context Example
```json
{
    "Proofpoint": {
        "Campaign": {
            "actors": [],
            "brands": [],
            "campaignMembers": [],
            "families": [
                {
                    "id": "69a63403-f478-40f6-a4cb-3d2ffb85b98e",
                    "name": "Keylogger"
                }
            ],
            "info": {
                "description": "Messages purporting to be e.g.\r\n\r\n* from &lt;xxxx@xxx.com;' and subject \"Re: New Order From customer\".\r\n\r\nThese messages contain compressed executables that lead to the installation of AgentTesla with the following example configuration:\r\n\r\n<pre>C2_Email_Address: xxxx@xxx.com\r\nC2_Email_Password: \r\nC2_Email_Server: xxxx@xxx.com</pre>",
                "id": "f3ff087dfgdfge-d05f97b2ed3f",
                "name": "AgentTesla | Compressed Executables | \"techie\" | 25 March 2021",
                "notable": false,
                "startDate": "2021-03-25T00:00:00.000Z"
            },
            "malware": [
                {
                    "id": "4b50dfbdfb-901a-1cb4cf8a21fb",
                    "name": "AgentTesla"
                }
            ],
            "techniques": [
                {
                    "id": "e488ddfbdfb20-a1aa-d1a85494067c",
                    "name": "Compressed Executable"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Campaign Information
>|Id|Name|Description|Start Date|Notable|
>|---|---|---|---|---|
>| f3ff08dfbdb5e-b3fe-d05f97b2ed3f | AgentTesla \| Compressed Executables \| "techie" \| 25 March 2021 | Messages purporting to be e.g.<br/><br/>* from &lt;xxxx@xxx.com&gt;' and subject "Re: New Order From customer".<br/><br/>These messages contain compressed executables that lead to the installation of AgentTesla with the following example configuration:<br/><br/><pre>C2_Email_Address: xxxx@xxx.com<br/>C2_Email_Password: <br/>C2_Email_Server: xxxx@xxx.com</pre> | 2021-03-25T00:00:00.000Z | false |
>
>### Campaign Members
>**No entries.**
>
>### Families
>|Id|Name|
>|---|---|
>| 69a63403-dbfdfb4cb-3d2ffb85b98e | Keylogger |
>
>### Techniques
>|Id|Name|
>|---|---|
>| e48835be-xcvxcvaa-d1a85494067c | Compressed Executable |
>
>### Actors
>**No entries.**
>
>### Brands
>**No entries.**
>
>### Malware
>|Id|Name|
>|---|---|
>| 4b500558-23d0-sfdsdf1cb4cf8a21fb | AgentTesla |


### proofpoint-list-most-attacked-users
***
Gets a list of the most attacked users in the organization.


#### Base Command

`proofpoint-list-most-attacked-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| window | An integer indicating how many days the data should be retrieved for. Possible values: "14", "30", "90". Possible values are: 14, 30, 90. Default is false. | Required | 
| limit | The maximum number of users to produce in the response. Default is 1000. | Optional | 
| page | The page of results to return. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.Vap.users | List | List of users in the organization. | 
| Proofpoint.Vap.totalVapUsers | Number | The total number of VAP users for the interval. | 
| Proofpoint.Vap.interval | String | An ISO8601-formatted interval showing the time the response was calculated for. | 
| Proofpoint.Vap.averageAttackIndex | Number | The average attack index value for users during the interval. | 
| Proofpoint.Vap.vapAttackIndexThreshold | Number | This interval's attack index threshold, past which a user is considered a VAP. | 


#### Command Example
```!proofpoint-list-most-attacked-users window="14"```

#### Context Example
```json
{
    "Proofpoint": {
        "Vap": {
            "averageAttackIndex": 307.05145,
            "interval": "2021-05-23T21:44:53Z/2021-06-06T21:44:53Z",
            "totalVapUsers": 1,
            "users": [
                {
                    "identity": {
                        "customerUserId": null,
                        "department": null,
                        "emails": [
                            "xxxx@xxx.com"
                        ],
                        "guid": "3b5132sdvsd76-c442-919e69175bdd",
                        "location": null,
                        "name": null,
                        "title": null,
                        "vip": false
                    },
                    "threatStatistics": {
                        "attackIndex": 4576,
                        "families": [
                            {
                                "name": "credential phishing",
                                "score": 7008
                            }
                        ]
                    }
                }
            ],
            "vapAttackIndexThreshold": 965.9637
        }
    }
}
```

#### Human Readable Output

>### Most Attacked Users Information
>|Total Vap Users|Interval|Average Attack Index|Vap Attack Index Threshold|
>|---|---|---|---|
>| 7 | 2021-05-23T21:44:53Z/2021-06-06T21:44:53Z | 307.05145 | 965.9637 |
>
>### Threat Families
>|Mailbox|Threat Family Name|Threat Score|
>|---|---|---|
>| xxxx@xxx.com | credential phishing | 7008 |


### proofpoint-get-top-clickers
***
Gets a list of the top clickers in the organization for a specified time period.


#### Base Command

`proofpoint-get-top-clickers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| window | An integer indicating how many days the data should be retrieved for. Possible values: "14", "30", "90". Possible values are: 14, 30, 90. Default is false. | Required | 
| limit | The maximum number of top clickers to produce in the response.The max supported value is 200. Default is 100. | Optional | 
| page | The page of results to return. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.Topclickers.users | List | List of users in the organization. | 
| Proofpoint.Topclickers.totalTopClickers | int | The total number of top clickers in the time interval. | 
| Proofpoint.Topclickers.interval | Date | An ISO8601-formatted interval showing the time the response was calculated for. | 


#### Command Example
```!proofpoint-get-top-clickers window="90"```

#### Context Example
```json
{
    "Proofpoint": {
        "Topclickers": {
            "interval": "2021-03-09T07:17:00Z/2021-06-07T07:17:00Z",
            "totalTopClickers": 1,
            "users": [
                {
                    "clickStatistics": {
                        "clickCount": 2,
                        "families": [
                            {
                                "clicks": 2,
                                "name": "Malware"
                            }
                        ]
                    },
                    "identity": {
                        "customerUserId": null,
                        "department": null,
                        "emails": [
                            "xxxx@xxx.come"
                        ],
                        "guid": "44fa5svfdgae-f22f-b49b49b1e4e3",
                        "location": null,
                        "name": null,
                        "title": null,
                        "vip": false
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Top Clickers Users Information
>|Total Top Clickers|Interval|
>|---|---|
>| 1 | 2021-03-09T07:17:00Z/2021-06-07T07:17:00Z |
>### Threat Families
>|Mailbox|Threat Family Name|Threat Score|
>|---|---|---|
>| xxxx@xxx.com | Malware |  |


### proofpoint-url-decode
***
Decodes URLs that have been rewritten by TAP to their original, target URL.


#### Base Command

`proofpoint-url-decode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | A comma-separated list of encoded URLs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Proofpoint.URL.encodedUrl | String | The original, rewritten URL supplied to the endpoint. | 
| Proofpoint.URL.decodedUrl | String | The target URL embedded inside the rewritten link. | 
| Proofpoint.URL.success | Boolean | Indicates whether the URL could successfully be decoded. | 


#### Command Example
```!proofpoint-url-decode urls="https://urldefense.proofpoint.com/v2/url?u=http-3A__links.mkt3337.com_ctt-3Fkn-3D3-26ms-3DMzQ3OTg3MDQS1-26r-3DMzkxNzk3NDkwMDA0S0-26b-3D0-26j-3DMTMwMjA1ODYzNQS2-26mt-3D1-26rt-3D0&d=DwMFaQ&c=Vxt5e0Osvvt2gflwSlsJ5DmPGcPvTRKLJyp031rXjhg&r=MujLDFBJstxoxZI_GKbsW7wxGM7nnIK__qZvVy6j9Wc&m=QJGhloAyfD0UZ6n8r6y9dF-khNKqvRAIWDRU_K65xPI&s=ew-rOtBFjiX1Hgv71XQJ5BEgl9TPaoWRm_Xp9Nuo8bk&e="```

#### Context Example
```json
{
    "Proofpoint": {
        "URL": {
            "decodedUrl": "http://links.mkt3337.com/ctt?kn=3&ms=MzQ3OTg3MDQS1&r=MzkxNzk3NDkwMDA0S0&b=0&j=MTMwMjA1ODYzNQS2&mt=1&rt=0",
            "encodedUrl": "https://urldefense.proofpoint.com/v2/url?u=http-3A__links.mkt3337.com_ctt-3Fkn-3D3-26ms-3DMzQ3OTg3MDQS1-26r-3DMzkxNzk3NDkwMDA0S0-26b-3D0-26j-3DMTMwMjA1ODYzNQS2-26mt-3D1-26rt-3D0&d=DwMFaQ&c=Vxt5e0Osvvt2gflwSlsJ5DmPGcPvTRKLJyp031rXjhg&r=MujLDFBJstxoxZI_GKbsW7wxGM7nnIK__qZvVy6j9Wc&m=QJGhloAyfD0UZ6n8r6y9dF-khNKqvRAIWDRU_K65xPI&s=ew-rOtBFjiX1Hgv71XQJ5BEgl9TPaoWRm_Xp9Nuo8bk&e=",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### URLs decoded information
>|Encoded Url|Decoded Url|
>|---|---|
>| https://urldefense.proofpoint.com/v2/url?u=http-3A__links.mkt3337.com_ctt-3Fkn-3D3-26ms-3DMzQ3OTg3MDQS1-26r-3DMzkxNzk3NDkwMDA0S0-26b-3D0-26j-3DMTMwMjA1ODYzNQS2-26mt-3D1-26rt-3D0&d=DwMFaQ&c=Vxt5e0Osvvt2gflwSlsJ5DmPGcPvTRKLJyp031rXjhg&r=MujLDFBJstxoxZI_GKbsW7wxGM7nnIK__qZvVy6j9Wc&m=QJGhloAyfD0UZ6n8r6y9dF-khNKqvRAIWDRU_K65xPI&s=ew-rOtBFjiX1Hgv71XQJ5BEgl9TPaoWRm_Xp9Nuo8bk&e= | http://links.mkt3337.com/ctt?kn=3&ms=MzQ3OTg3MDQS1&r=MzkxNzk3NDkwMDA0S0&b=0&j=MTMwMjA1ODYzNQS2&mt=1&rt=0 |
