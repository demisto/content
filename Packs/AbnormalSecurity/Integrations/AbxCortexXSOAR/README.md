Abnormal Security detects the whole spectrum of email attacks, from vendor email compromise and spear-phishing to unwanted email spam and graymail. To stop these advanced attacks, Abnormal leverages the industry’s most advanced behavioral data science to baseline known good behavior and detects anomalies.
This integration was integrated and tested with version 1.3.0 of Abnormal Security Client API
## Configure Abnormal Security Client API on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Abnormal Security Client API.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://api.abnormalplatform.com/v1) | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### abxcortexxsoar-check-the-status-of-an-action-requested-on-a-case
***
Check the status of an action requested on a case.


#### Base Command

`abxcortexxsoar-check-the-status-of-an-action-requested-on-a-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | A string representing the case. | Required | 
| actionId | A UUID representing the action id for a case. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbxCortexXSOAR.ActionStatus.status | String |  | 
| AbxCortexXSOAR.ActionStatus.description | String |  | 


#### Command Example
```!abxcortexxsoar-check-the-status-of-an-action-requested-on-a-case caseId=12345 actionId=abcdefgh-1234-5678-ijkl-mnop9qrstuvwx```

#### Context Example
```json
{
    "AbxCortexXSOAR": {
        "ActionStatus": {
            "description": "The request was completed successfully",
            "status": "acknowledged"
        }
    }
}
```

#### Human Readable Output

>### Results
>|description|status|
>|---|---|
>| The request was completed successfully | acknowledged |


### abxcortexxsoar-check-the-status-of-an-action-requested-on-a-threat
***
Check the status of an action requested on a threat.


#### Base Command

`abxcortexxsoar-check-the-status-of-an-action-requested-on-a-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threatId | A UUID representing the threat. | Required | 
| actionId | A UUID representing the action id for a threat. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbxCortexXSOAR.ActionStatus.status | String |  | 
| AbxCortexXSOAR.ActionStatus.description | String |  | 


#### Command Example
```!abxcortexxsoar-check-the-status-of-an-action-requested-on-a-threat threatId=xwvutsrq-9pon-mlkj-i876-54321hgfedcba actionId=abcdefgh-1234-5678-ijkl-mnop9qrstuvwx```

#### Context Example
```json
{
    "AbxCortexXSOAR": {
        "ActionStatus": {
            "description": "The request was completed successfully",
            "status": "acknowledged"
        }
    }
}
```

#### Human Readable Output

>### Results
>|description|status|
>|---|---|
>| The request was completed successfully | acknowledged |


### abxcortexxsoar-get-a-list-of-abnormal-cases-identified-by-abnormal-security
***
Get a list of Abnormal cases identified by Abnormal Security


#### Base Command

`abxcortexxsoar-get-a-list-of-abnormal-cases-identified-by-abnormal-security`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Value must be of the format `filter={FILTER KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ`. A `{FILTER KEY}` must be specified, and currently the only key that is supported for `/cases` is `lastModifiedTime`. At least 1 of `gte`/`lte` must be specified, with a datetime string following the `YYYY-MM-DDTHH:MM:SSZ` format. | Optional | 
| pageSize | Number of cases that on in each page. Each page of data will have at most pageSize threats. Has no effect if filter is not specified. | Optional | 
| pageNumber | 1-indexed page number to get a particular page of cases. Has no effect if filter is not specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbxCortexXSOAR.inline_response_200_1.cases.caseId | String | A unique identifier for this case. | 
| AbxCortexXSOAR.inline_response_200_1.cases.severity | String | Description of the severity level for this case. | 
| AbxCortexXSOAR.inline_response_200_1.pageNumber | Number | The current page number. Will not be be in the response if no filter query  meter is passed in via the request. | 
| AbxCortexXSOAR.inline_response_200_1.nextPageNumber | Number | The next page number. Wil not be includedin the response if there are no more pages of data or if  no filter query  meter is passed in via the request | 


#### Command Example
```!abxcortexxsoar-get-a-list-of-abnormal-cases-identified-by-abnormal-security```

#### Context Example
```json
{
    "AbxCortexXSOAR": {
        "inline_response_200_1": {
            "cases": [
                {
                    "caseId": "1234",
                    "severity": "Potential Account Takeover"
                }
            ],
            "nextPageNumber": 2,
            "pageNumber": 1
        }
    }
}
```

#### Human Readable Output

>### Results
>|cases|nextPageNumber|pageNumber|
>|---|---|---|
>| {'caseId': '1234', 'severity': 'Potential Account Takeover'} | 2 | 1 |


### abxcortexxsoar-get-a-list-of-threats
***
Get a list of threats


#### Base Command

`abxcortexxsoar-get-a-list-of-threats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Value must be of the format `filter={FILTER KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ`. A `{FILTER KEY}` must be specified, and currently the only keys that are supported for `/threats` are `receivedTime` and `lastModifiedTime`. At least 1 of `gte`/`lte` must be specified, with a datetime string following the `YYYY-MM-DDTHH:MM:SSZ format`. | Optional | 
| pageSize | Number of threats that on in each page. Each page of data will have at most pageSize threats. Has no effect if filter is not specified. | Optional | 
| pageNumber | 1-indexed page number to get a particular page of threats. Has no effect if filter is not specified. | Optional | 
| source | Filters threats based on the source of detection. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbxCortexXSOAR.inline_response_200.threats.threatId | String | An id which maps to a threat campaign. A threat campaign might be received by multiple users. | 
| AbxCortexXSOAR.inline_response_200.pageNumber | Number | The current page number. Will not be be in the response if no filter query  meter is passed in via the request. | 
| AbxCortexXSOAR.inline_response_200.nextPageNumber | Number | The next page number. Wil not be includedin the response if there are no more pages of data or if  no filter query  meter is passed in via the request | 


#### Command Example
```!abxcortexxsoar-get-a-list-of-threats```

#### Context Example
```json
{
    "AbxCortexXSOAR": {
        "inline_response_200": {
            "nextPageNumber": 2,
            "pageNumber": 1,
            "threats": [
                {
                    "threatId": "184712ab-6d8b-47b3-89d3-a314efef79e2"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|nextPageNumber|pageNumber|threats|
>|---|---|---|
>| 2 | 1 | {'threatId': '184712ab-6d8b-47b3-89d3-a314efef79e2'} |


### abxcortexxsoar-get-details-of-a-threat
***
Get details of a threat


#### Base Command

`abxcortexxsoar-get-details-of-a-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threatId | A UUID representing the threat. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbxCortexXSOAR.ThreatDetails.threatId | String | An id which maps to a threat campaign. A threat campaign might be received by multiple users. | 
| AbxCortexXSOAR.ThreatDetails.messages.threatId | String | An id which maps to a threat campaign. A threat campaign might be received by multiple users. | 
| AbxCortexXSOAR.ThreatDetails.messages.abxMessageId | Unknown | A unique identifier for an individual message within a threat \(i.e email campaign\). | 
| AbxCortexXSOAR.ThreatDetails.messages.abxPortalUrl | String | The URL at which the specific message details are viewable in Abnormal Security's Portal web interface. | 
| AbxCortexXSOAR.ThreatDetails.messages.subject | String | The email subject. | 
| AbxCortexXSOAR.ThreatDetails.messages.fromAddress | String | The email address of the sender. | 
| AbxCortexXSOAR.ThreatDetails.messages.fromName | String | The display name of the sender. | 
| AbxCortexXSOAR.ThreatDetails.messages.toAddresses | String | All the email addresses to which the message was sent, comma-se ted &amp; truncated at 255 chars. | 
| AbxCortexXSOAR.ThreatDetails.messages.recipientAddress | String | the email address of the user who actually received the message. | 
| AbxCortexXSOAR.ThreatDetails.messages.receivedTime | String | The timestamp at which this message arrived. | 
| AbxCortexXSOAR.ThreatDetails.messages.sentTime | String | The timestamp at which this message was sent. | 
| AbxCortexXSOAR.ThreatDetails.messages.internetMessageId | String | The internet message ID, per RFC 822 | 
| AbxCortexXSOAR.ThreatDetails.messages.autoRemediated | Boolean | Abnormal has automatically detected and remediated this message from the user's mailbox. | 
| AbxCortexXSOAR.ThreatDetails.messages.postRemediated | Boolean | Email campaigns that were remediated at a later time, after landing in user's mailbox. | 
| AbxCortexXSOAR.ThreatDetails.messages.attackType | String | The type of threat the message represents. | 
| AbxCortexXSOAR.ThreatDetails.messages.attackStrategy | String |  | 
| AbxCortexXSOAR.ThreatDetails.messages.returnPath | String |  | 
| AbxCortexXSOAR.ThreatDetails.messages.senderIpAddress | String | IP address of sender. | 
| AbxCortexXSOAR.ThreatDetails.messages.impersonatedParty | String | Impersonated party, if any. | 
| AbxCortexXSOAR.ThreatDetails.messages.attackVector | String | The attack medium. | 
| AbxCortexXSOAR.ThreatDetails.messages.remediationTimestamp | String | The timestamp at which this message was remediated, or empty if it has not been remediated. | 
| AbxCortexXSOAR.ThreatDetails.messages.isRead | Boolean | Whether an email has been read | 
| AbxCortexXSOAR.ThreatDetails.messages.attackedParty | String | The party that was targeted by an attack. | 


#### Command Example
```!abxcortexxsoar-get-details-of-a-threat threatId=xwvutsrq-9pon-mlkj-i876-54321hgfedcba```

#### Context Example
```json
{
    "AbxCortexXSOAR": {
        "ThreatDetails": {
            "messages": [
                {
                    "abxMessageId": 4551618356913732000,
                    "abxPortalUrl": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/4551618356913732076",
                    "attachmentNames": [
                        "attachment.pdf"
                    ],
                    "attackStrategy": "Name Impersonation",
                    "attackType": "Extortion",
                    "attackVector": "Text",
                    "attackedParty": "VIP",
                    "autoRemediated": true,
                    "ccEmails": [
                        "cc@example.com"
                    ],
                    "fromAddress": "support@secure-reply.org",
                    "fromName": "",
                    "impersonatedParty": "None / Others",
                    "internetMessageId": "<5edfca1c.1c69fb81.4b055.8fd5@mx.google.com>",
                    "isRead": true,
                    "postRemediated": true,
                    "receivedTime": "2020-06-09T17:42:59Z",
                    "recipientAddress": "example@example.com",
                    "remediationTimestamp": "2020-06-09T17:42:59Z",
                    "replyToEmails": [
                        "reply-to@example.com"
                    ],
                    "returnPath": "support@secure-reply.org",
                    "senderIpAddress": "100.101.102.103",
                    "sentTime": "2020-06-09T17:42:59Z",
                    "subject": "Phishing Email",
                    "summaryInsights": [
                        "Bitcoin Topics",
                        "Personal Information Theft",
                        "Unusual Sender"
                    ],
                    "threatId": "184712ab-6d8b-47b3-89d3-a314efef79e2",
                    "toAddresses": "example@example.com, another@example.com",
                    "urls": [
                        "https://www.google.com/"
                    ]
                }
            ],
            "threatId": "184712ab-6d8b-47b3-89d3-a314efef79e2"
        }
    }
}
```

#### Human Readable Output

>### Results
>|messages|threatId|
>|---|---|
>| {'threatId': '184712ab-6d8b-47b3-89d3-a314efef79e2', 'abxMessageId': 4551618356913732000, 'abxPortalUrl': 'https://portal.abnormalsecurity.com/home/threat-center/remediation-history/4551618356913732076', 'subject': 'Phishing Email', 'fromAddress': 'support@secure-reply.org', 'fromName': '', 'toAddresses': 'example@example.com, another@example.com', 'recipientAddress': 'example@example.com', 'receivedTime': '2020-06-09T17:42:59Z', 'sentTime': '2020-06-09T17:42:59Z', 'internetMessageId': '<5edfca1c.1c69fb81.4b055.8fd5@mx.google.com>', 'autoRemediated': True, 'postRemediated': True, 'attackType': 'Extortion', 'attackStrategy': 'Name Impersonation', 'returnPath': 'support@secure-reply.org', 'replyToEmails': ['reply-to@example.com'], 'ccEmails': ['cc@example.com'], 'senderIpAddress': '100.101.102.103', 'impersonatedParty': 'None / Others', 'attackVector': 'Text', 'attachmentNames': ['attachment.pdf'], 'urls': ['https://www.google.com/'], 'summaryInsights': ['Bitcoin Topics', 'Personal Information Theft', 'Unusual Sender'], 'remediationTimestamp': '2020-06-09T17:42:59Z', 'isRead': True, 'attackedParty': 'VIP'} | 184712ab-6d8b-47b3-89d3-a314efef79e2 |


### abxcortexxsoar-get-details-of-an-abnormal-case
***
Get details of an Abnormal case


#### Base Command

`abxcortexxsoar-get-details-of-an-abnormal-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | A string representing the case. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbxCortexXSOAR.AbnormalCaseDetails.caseId | String | A unique identifier for this case. | 
| AbxCortexXSOAR.AbnormalCaseDetails.severity | String | Description of the severity level for this case. | 
| AbxCortexXSOAR.AbnormalCaseDetails.affectedEmployee | String | Which employee this case pertains to. | 
| AbxCortexXSOAR.AbnormalCaseDetails.firstObserved | String | First time suspicious behavior was observed. | 


#### Command Example
```!abxcortexxsoar-get-details-of-an-abnormal-case caseId=12345```

#### Context Example
```json
{
    "AbxCortexXSOAR": {
        "AbnormalCaseDetails": {
            "affectedEmployee": "FirstName LastName",
            "caseId": "1234",
            "firstObserved": "2020-06-09T17:42:59Z",
            "severity": "Potential Account Takeover",
            "threatIds": [
                "184712ab-6d8b-47b3-89d3-a314efef79e2"
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|affectedEmployee|caseId|firstObserved|severity|threatIds|
>|---|---|---|---|---|
>| FirstName LastName | 1234 | 2020-06-09T17:42:59Z | Potential Account Takeover | 184712ab-6d8b-47b3-89d3-a314efef79e2 |


### abxcortexxsoar-get-the-latest-threat-intel-feed
***
Get the latest threat intel feed.


#### Base Command

`abxcortexxsoar-get-the-latest-threat-intel-feed`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### abxcortexxsoar-manage-a-threat-identified-by-abnormal-security
***
Manage a Threat identified by Abnormal Security


#### Base Command

`abxcortexxsoar-manage-a-threat-identified-by-abnormal-security`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threatId | A UUID representing the threat. | Required | 
| action | Action to perform on threat. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!abxcortexxsoar-manage-a-threat-identified-by-abnormal-security threatId=xwvutsrq-9pon-mlkj-i876-54321hgfedcba action=remediate```

#### Context Example
```json
{
    "AbxCortexXSOAR": {
        "action_id": "a33a212a-89ff-461f-be34-ea52aff44a73",
        "status_url": "https://api.abnormalplatform.com/v1/threats/184712ab-6d8b-47b3-89d3-a314efef79e2/actions/a33a212a-89ff-461f-be34-ea52aff44a73"
    }
}
```

#### Human Readable Output

>### Results
>|action_id|status_url|
>|---|---|
>| a33a212a-89ff-461f-be34-ea52aff44a73 | https://api.abnormalplatform.com/v1/threats/184712ab-6d8b-47b3-89d3-a314efef79e2/actions/a33a212a-89ff-461f-be34-ea52aff44a73 |


### abxcortexxsoar-manage-an-abnormal-case
***
Manage an Abnormal Case.


#### Base Command

`abxcortexxsoar-manage-an-abnormal-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | A string representing the case. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!abxcortexxsoar-manage-an-abnormal-case caseId=12345 action=unremediate```

#### Context Example
```json
{
    "AbxCortexXSOAR": {
        "action_id": "61e76395-40d3-4d78-b6a8-8b17634d0f5b",
        "status_url": "https://api.abnormalplatform.com/v1/cases/1234/actions/61e76395-40d3-4d78-b6a8-8b17634d0f5b"
    }
}
```

#### Human Readable Output

>### Results
>|action_id|status_url|
>|---|---|
>| 61e76395-40d3-4d78-b6a8-8b17634d0f5b | https://api.abnormalplatform.com/v1/cases/1234/actions/61e76395-40d3-4d78-b6a8-8b17634d0f5b |


### abxcortexxsoar-submit-an-inquiry-to-request-a-report-on-misjudgement-by-abnormal-security
***
Submit an Inquiry to request a report on misjudgement by Abnormal Security


#### Base Command

`abxcortexxsoar-submit-an-inquiry-to-request-a-report-on-misjudgement-by-abnormal-security`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!abxcortexxsoar-submit-an-inquiry-to-request-a-report-on-misjudgement-by-abnormal-security```

#### Human Readable Output
```Thank you for your feedback! We have sent your inquiry to our support staff.```


