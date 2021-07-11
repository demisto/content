Abnormal Security detects the whole spectrum of email attacks, from vendor email compromise and spear-phishing to unwanted email spam and graymail. To stop these advanced attacks, Abnormal leverages the industry’s most advanced behavioral data science to baseline known good behavior and detects anomalies.
This integration was integrated and tested with version 1.3.0 of Abnormal Security
## Configure Abnormal Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Abnormal Security.
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
### abnormal-security-check-case-action-status
***
Check the status of an action requested on a case.


#### Base Command

`abnormal-security-check-case-action-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | A string representing the email case. Can be retrieved by first running command to list cases. | Required | 
| action_id | A string representing the email case. Can be retrieved from payload after performing an action on a case. | Required | 
| mock-data | Returns test data if set to `True`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbnormalSecurity.ActionStatus.status | String | Status of the case after an action is performed | 
| AbnormalSecurity.ActionStatus.description | String | Detailed description of the status | 


#### Command Example
```!abnormal-security-check-case-action-status case_id=12345 action_id=abcdefgh-1234-5678-ijkl-mnop9qrstuvwx```

#### Context Example
```json
{
    "AbnormalSecurity": {
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


### abnormal-security-check-threat-action-status
***
Check the status of an action requested on a threat.


#### Base Command

`abnormal-security-check-threat-action-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | A UUID representing a threat campaign. Full list of threat IDs can be obtained by first running the command to list a threat. | Required | 
| action_id | A UUID representing the action id for a threat. Can be obtained from payload after performing an action on the threat. | Required | 
| mock-data | Returns test data if set to `True`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbnormalSecurity.ActionStatus.status | String | The status of a threat after performing an action on it | 
| AbnormalSecurity.ActionStatus.description | String | The description of the status | 


#### Command Example
```!abnormal-security-check-threat-action-status threat_id=xwvutsrq-9pon-mlkj-i876-54321hgfedcba action_id=abcdefgh-1234-5678-ijkl-mnop9qrstuvwx```

#### Context Example
```json
{
    "AbnormalSecurity": {
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


### abnormal-security-list-abnormal-cases
***
Get a list of Abnormal cases identified by Abnormal Security


#### Base Command

`abnormal-security-list-abnormal-cases`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Value must be of the format `filter={FILTER KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ`. A `{FILTER KEY}` must be specified, and currently the only key that is supported for `/cases` is `lastModifiedTime`. At least 1 of `gte`/`lte` must be specified, with a datetime string following the `YYYY-MM-DDTHH:MM:SSZ` format. | Optional | 
| page_size | Number of cases that are on each page. Each page of data will have at most page_size threats. Has no effect if filter is not specified. | Optional | 
| page_number | 1-indexed page number to get a particular page of cases. Has no effect if filter is not specified. | Optional | 
| mock-data | Returns test data if set to `True`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbnormalSecurity.inline_response_200_1.cases.caseId | String | A unique identifier for this case. | 
| AbnormalSecurity.inline_response_200_1.cases.description | String | Description of the severity level for this case. | 
| AbnormalSecurity.inline_response_200_1.pageNumber | Number | The current page number. Will not be be in the response if no filter query meter is passed in via the request. | 
| AbnormalSecurity.inline_response_200_1.nextpageNumber | Number | The next page number. Will not be included in the response if there are no more pages of data or if no filter query meter is passed in via the request | 


#### Command Example
```!abnormal-security-list-abnormal-cases filter="gte 2020-12-01T01:01:01Z"```

#### Context Example
```json
{
    "AbnormalSecurity": {
        "inline_response_200_1": {
            "cases": [
                {
                    "caseId": "1234",
                    "description": "Potential Account Takeover"
                }
            ],
            "nextPageNumber": 2,
            "pageNumber": 1
        }
    }
}
```

#### Human Readable Output

>### List of Cases
>### Case IDs
>|caseId|severity|
>|---|---|
>| 1234 |  |


### abnormal-security-list-threats
***
Get a list of threats


#### Base Command

`abnormal-security-list-threats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Value must be of the format `filter={FILTER KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ`. A `{FILTER KEY}` must be specified, and currently the only keys that are supported for `/threats` are `receivedTime` and `lastModifiedTime`. At least 1 of `gte`/`lte` must be specified, with a datetime string following the `YYYY-MM-DDTHH:MM:SSZ format`. | Optional | 
| page_size | Number of threats that on in each page. Each page of data will have at most page_size threats. Has no effect if filter is not specified. | Optional | 
| page_number | 1-indexed page number to get a particular page of threats. Has no effect if filter is not specified. | Optional | 
| mock-data | Returns test data if set to `True`. | Optional | 
| source | Filters threats based on the source of detection. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbnormalSecurity.inline_response_200.threats.threatId | String | An id which maps to a threat campaign. A threat campaign might be received by multiple users. | 
| AbnormalSecurity.inline_response_200.pageNumber | Number | The current page number. Will not be be in the response if no filter query  meter is passed in via the request. | 
| AbnormalSecurity.inline_response_200.nextpageNumber | Number | The next page number. Will not be included in the response if there are no more pages of data or if no filter query meter is passed in via the request | 


#### Command Example
```!abnormal-security-list-threats filter="gte 2020-12-01T01:01:01Z"```

#### Context Example
```json
{
    "AbnormalSecurity": {
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

>### List of Threats
>### Threat IDs
>|threatId|
>|---|
>| 184712ab-6d8b-47b3-89d3-a314efef79e2 |


### abnormal-security-get-threat
***
Get details of a threat


#### Base Command

`abnormal-security-get-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | A UUID representing a threat campaign. Full list of threat IDs can be obtained by first running the command to list a threat. | Required | 
| mock-data | Returns test data if set to `True`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbnormalSecurity.ThreatDetails.threatId | String | An id which maps to a threat campaign. A threat campaign might be received by multiple users. | 
| AbnormalSecurity.ThreatDetails.messages.threatId | String | An id which maps to a threat campaign. A threat campaign might be received by multiple users. | 
| AbnormalSecurity.ThreatDetails.messages.abxMessageId | Number | A unique identifier for an individual message within a threat \(i.e email campaign\). | 
| AbnormalSecurity.ThreatDetails.messages.abxPortalUrl | String | The URL at which the specific message details are viewable in Abnormal Security's Portal web interface. | 
| AbnormalSecurity.ThreatDetails.messages.subject | String | The email subject. | 
| AbnormalSecurity.ThreatDetails.messages.fromAddress | String | The email address of the sender. | 
| AbnormalSecurity.ThreatDetails.messages.fromName | String | The display name of the sender. | 
| AbnormalSecurity.ThreatDetails.messages.toAddresses | String | All the email addresses to which the message was sent, comma-se ted &amp; truncated at 255 chars. | 
| AbnormalSecurity.ThreatDetails.messages.recipientAddress | String | the email address of the user who actually received the message. | 
| AbnormalSecurity.ThreatDetails.messages.receivedTime | String | The timestamp at which this message arrived. | 
| AbnormalSecurity.ThreatDetails.messages.sentTime | String | The timestamp at which this message was sent. | 
| AbnormalSecurity.ThreatDetails.messages.internetMessageId | String | The internet message ID, per RFC 822 | 
| AbnormalSecurity.ThreatDetails.messages.autoRemediated | Boolean | Abnormal has automatically detected and remediated this message from the user's mailbox. | 
| AbnormalSecurity.ThreatDetails.messages.postRemediated | Boolean | Email campaigns that were remediated at a later time, after landing in user's mailbox. | 
| AbnormalSecurity.ThreatDetails.messages.attackType | String | The type of threat the message represents. | 
| AbnormalSecurity.ThreatDetails.messages.attackStrategy | String | The attack strategy identified to be used by a threat campaign | 
| AbnormalSecurity.ThreatDetails.messages.returnPath | String | The potential path where information is returned to the attacker | 
| AbnormalSecurity.ThreatDetails.messages.senderIpAddress | String | IP address of sender. | 
| AbnormalSecurity.ThreatDetails.messages.impersonatedParty | String | Impersonated party, if any. | 
| AbnormalSecurity.ThreatDetails.messages.attackVector | String | The attack medium. | 
| AbnormalSecurity.ThreatDetails.messages.remediationTimestamp | String | The timestamp at which this message was remediated, or empty if it has not been remediated. | 
| AbnormalSecurity.ThreatDetails.messages.isRead | Boolean | Whether an email has been read | 
| AbnormalSecurity.ThreatDetails.messages.attackedParty | String | The party that was targeted by an attack. | 


#### Command Example
```!abnormal-security-get-threat threat_id=xwvutsrq-9pon-mlkj-i876-54321hgfedcba```

#### Context Example
```json
{
    "AbnormalSecurity": {
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

>### Messages in Threat xwvutsrq-9pon-mlkj-i876-54321hgfedcba
>|subject|fromAddress|fromName|toAddresses|recipientAddress|receivedTime|attackType|attackStrategy|returnPath|
>|---|---|---|---|---|---|---|---|---|
>| Phishing Email | support@secure-reply.org |  | example@example.com, another@example.com | example@example.com | 2020-06-09T17:42:59Z | Extortion | Name Impersonation | support@secure-reply.org |


### abnormal-security-get-abnormal-case
***
Get details of an Abnormal case


#### Base Command

`abnormal-security-get-abnormal-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | A string representing the email case. Can be retrieved by first running command to list cases. | Required | 
| mock-data | Returns test data if set to `True`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbnormalSecurity.AbnormalCaseDetails.caseId | String | A unique identifier for this case. | 
| AbnormalSecurity.AbnormalCaseDetails.severity | String | Description of the severity level for this case. | 
| AbnormalSecurity.AbnormalCaseDetails.affectedEmployee | String | Which employee this case pertains to. | 
| AbnormalSecurity.AbnormalCaseDetails.firstObserved | String | First time suspicious behavior was observed. | 


#### Command Example
```!abnormal-security-get-abnormal-case case_id=1234```

#### Context Example
```json
{
    "AbnormalSecurity": {
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

>### Details of Case 1234
>|caseId|severity|affectedEmployee|firstObserved|threatIds|
>|---|---|---|---|---|
>| 1234 | Potential Account Takeover | FirstName LastName | 2020-06-09T17:42:59Z | 184712ab-6d8b-47b3-89d3-a314efef79e2 |


### abnormal-security-get-latest-threat-intel-feed
***
Get the latest threat intel feed.


#### Base Command

`abnormal-security-get-latest-threat-intel-feed`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mock-data | Returns test data if set to `True`. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!abnormal-security-get-latest-threat-intel-feed```

#### Human Readable Output



### abnormal-security-manage-threat
***
Manage a Threat identified by Abnormal Security


#### Base Command

`abnormal-security-manage-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | A UUID representing a threat campaign. Full list of threat IDs can be obtained by first running the command to list a threat. | Required | 
| action | Action to perform on threat. | Required | 
| mock-data | Returns test data if set to `True`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbnormalSecurity.ThreatManageResults.action_id | String | ID of the action taken | 
| AbnormalSecurity.ThreatManageResults.status_url | String | URL of the status of the action | 


#### Command Example
```!abnormal-security-manage-threat threat_id=xwvutsrq-9pon-mlkj-i876-54321hgfedcba action=remediate```

#### Context Example
```json
{
    "AbnormalSecurity": {
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


### abnormal-security-manage-abnormal-case
***
Manage an Abnormal Case.


#### Base Command

`abnormal-security-manage-abnormal-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | A string representing the email case. Can be retrieved by first running command to list cases. | Required | 
| action | Action to perform on case. | Required | 
| mock-data | Returns test data if set to `True`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbnormalSecurity.CaseManageResults.action_id | String | ID of the action taken | 
| AbnormalSecurity.CaseManageResults.status_url | String | URL of the status of the action | 


#### Command Example
```!abnormal-security-manage-abnormal-case case_id=1234 action=action_required```

#### Context Example
```json
{
    "AbnormalSecurity": {
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


### abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement
***
Submit an Inquiry to request a report on misjudgement by Abnormal Security


#### Base Command

`abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mock-data | Returns test data if set to `True`. | Optional | 
| reporter | Email of the reporter. | Required | 
| report_type | Type of misjudgement reported. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbnormalSecurity.SubmitInquiry.detail | String | Confirmation of successfully sending inquiry | 


#### Command Example
```!abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement reporter=abc@def.com report_type=false-positive```

#### Context Example
```json
{
    "AbnormalSecurity": {
        "detail": "Thank you for your feedback! We have sent your inquiry to our support staff."
    }
}
```

#### Human Readable Output

>### Results
>|detail|
>|---|
>| Thank you for your feedback! We have sent your inquiry to our support staff. |

