Abnormal Security detects the whole spectrum of email attacks, from vendor email compromise and spear-phishing to unwanted email spam and graymail. To stop these advanced attacks, Abnormal leverages the industry’s most advanced behavioral data science to baseline known good behavior and detects anomalies.
This integration was integrated and tested with version 1.3.0 of Abnormal Security

## Configure Abnormal Security in Cortex


| **Parameter**                                         | **Required** |
| ----------------------------------------------------- | ------------ |
| Server URL (e.g. https://api.abnormalplatform.com/v1) | True         |
| API Key                                               | True         |
| Trust any certificate (not secure)                    | False        |
| Use system proxy settings                             | False        |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### abnormal-security-check-case-action-status

---

Check the status of an action requested on a case.

#### Base Command

`abnormal-security-check-case-action-status`

#### Input

| **Argument Name** | **Description**                                                                                           | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------- | ------------ |
| case_id           | A string representing the email case. Can be retrieved by first running command to list cases.            | Required     |
| action_id         | A string representing the email case. Can be retrieved from payload after performing an action on a case. | Required     |
| mock-data         | Returns test data if set to `True`.                                                                       | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                                    | Optional     |

#### Context Output

| **Path**                                  | **Type** | **Description**                                 |
| ----------------------------------------- | -------- | ----------------------------------------------- |
| AbnormalSecurity.ActionStatus.status      | String   | Status of the case after an action is performed |
| AbnormalSecurity.ActionStatus.description | String   | Detailed description of the status              |

#### Command Example

`!abnormal-security-check-case-action-status case_id=12345 action_id=abcdefgh-1234-5678-ijkl-mnop9qrstuvwx`

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

> ### Results
>
> | description                            | status       |
> | -------------------------------------- | ------------ |
> | The request was completed successfully | acknowledged |

### abnormal-security-check-threat-action-status

---

Check the status of an action requested on a threat.

#### Base Command

`abnormal-security-check-threat-action-status`

#### Input

| **Argument Name** | **Description**                                                                                                               | **Required** |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------ |
| threat_id         | A UUID representing a threat campaign. Full list of threat IDs can be obtained by first running the command to list a threat. | Required     |
| action_id         | A UUID representing the action id for a threat. Can be obtained from payload after performing an action on the threat.        | Required     |
| mock-data         | Returns test data if set to `True`.                                                                                           | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                                                        | Optional     |

#### Context Output

| **Path**                                  | **Type** | **Description**                                         |
| ----------------------------------------- | -------- | ------------------------------------------------------- |
| AbnormalSecurity.ActionStatus.status      | String   | The status of a threat after performing an action on it |
| AbnormalSecurity.ActionStatus.description | String   | The description of the status                           |

#### Command Example

`!abnormal-security-check-threat-action-status threat_id=xwvutsrq-9pon-mlkj-i876-54321hgfedcba action_id=abcdefgh-1234-5678-ijkl-mnop9qrstuvwx`

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

> ### Results
>
> | description                            | status       |
> | -------------------------------------- | ------------ |
> | The request was completed successfully | acknowledged |

### abnormal-security-download-threat-log-csv

---

Download data from Threat Log in .csv format

#### Base Command

`abnormal-security-download-threat-log-csv`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                   | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| filter            | Filter the results based on a filter key. Value must be of the format `filter={FILTER KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ`. Supported keys - [`receivedTime`]. | Optional     |
| mock-data         | Returns test data if set to `True`.                                                                                                                                               | Optional     |
| source            | Filters threats based on the source of detection.                                                                                                                                 | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                                                                                                            | Optional     |

#### Context Output

There is no context output for this command.

#### Command Example

`!abnormal-security-download-threat-log-csv filter="receivedTime gte 2020-12-01T01:01:01Z"`

#### Context Example

```json
{
    "File": {
        "EntryID": "2294@2ef16ace-2149-42b9-8b0f-fb7620ba7d44",
        "Extension": "csv",
        "Info": "csv",
        "MD5": "a981545ee72fe115888800725883ca8a",
        "Name": "threat_log.csv",
        "SHA1": "c3cbae11542dc7244e3bf04a0901d7063597d381",
        "SHA256": "296463cad959803d64bfc94fbffa24e30c9438ba58827a100a9e7c219f26b382",
        "SHA512": "21a53f61c7d22b533abd7181b16116bf9017b7a444c10e4d2336803794ef0d9dded56e65179f924252f0bf3231e35fa1b726c8d7723f10b2f08bae0b3bedddd1",
        "SSDeep": "12:dB2XRzmZIm88Rvu8R7b7+I78RQC5+GUHwgfdvvq:dB2XRMrt/C5+GYw",
        "Size": 449,
        "Type": "ASCII text, with CRLF line terminators"
    }
}
```

### abnormal-security-list-abuse-mailbox-campaigns

---

Get a list of campaigns submitted to Abuse Mailbox

#### Base Command

`abnormal-security-list-abuse-mailbox-campaigns`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                            | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------ |
| filter            | Value must be of the format `filter={FILTER KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ`. A `{FILTER KEY}` must be specified, and currently only the key `lastReportedTime` is supported for `/abusecampaigns`. At least one of `gte`/`lte` must be specified, with a datetime string following the `YYYY-MM-DDTHH:MM:SSZ` format. Do note that provided filter time is in UTC. | Optional     |
| page_size         | Number of abuse campaigns shown on each page. Each page of data will have at most page_size abuse campaign IDs.                                                                                                                                                                                                                                                                            | Optional     |
| page_number       | 1-indexed page number to get a particular page of threats. Has no effect if filter is not specified.                                                                                                                                                                                                                                                                                       | Optional     |
| mock-data         | Returns test data if set to `True`.                                                                                                                                                                                                                                                                                                                                                        | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                                                                                                                                                                                                                                                                                                                     | Optional     |

#### Context Output

| **Path**                                            | **Type** | **Description**                        |
| --------------------------------------------------- | -------- | -------------------------------------- |
| AbnormalSecurity.AbuseCampaign.campaigns.campaignId | String   | An id which maps to an abuse campaign. |
| AbnormalSecurity.AbuseCampaign.pageNumber           | Number   | The current page number.               |
| AbnormalSecurity.AbuseCampaign.nextPageNumber       | Number   | The next page number.                  |

#### Command Example

`!abnormal-security-list-abuse-mailbox-campaigns filter="lastReportedTime gte 2020-12-01T01:01:01Z"`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "AbuseCampaign": {
            "campaigns": [
                {
                    "campaignId": "fff51768-c446-34e1-97a8-9802c29c3ebd"
                },
                {
                    "campaignId": "07434ea5-df7b-3ff4-8d07-4a82df0c655d"
                }
            ],
            "pageNumber": 1
        }
    }
}
```

#### Human Readable Output

> ### List of Abuse Mailbox Campaigns
>
> ### Campaign IDs
>
> | campaignId                           |
> | ------------------------------------ |
> | fff51768-c446-34e1-97a8-9802c29c3ebd |
> | 07434ea5-df7b-3ff4-8d07-4a82df0c655d |

### abnormal-security-list-abnormal-cases

---

Get a list of Abnormal cases identified by Abnormal Security

#### Base Command

`abnormal-security-list-abnormal-cases`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                            | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------ |
| filter            | Value must be of the format `filter={FILTER KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ`. A `{FILTER KEY}` must be specified, and currently the only key that is supported for `/cases` is `lastModifiedTime`. At least 1 of `gte`/`lte` must be specified, with a datetime string following the `YYYY-MM-DDTHH:MM:SSZ` format. | Optional     |
| page_size         | Number of cases that are on each page. Each page of data will have at most page_size threats. Has no effect if filter is not specified.                                                                                                                                                                                                    | Optional     |
| page_number       | 1-indexed page number to get a particular page of cases. Has no effect if filter is not specified.                                                                                                                                                                                                                                         | Optional     |
| mock-data         | Returns test data if set to `True`.                                                                                                                                                                                                                                                                                                        | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                                                                                                                                                                                                                                                                     | Optional     |

#### Context Output

| **Path**                                                 | **Type** | **Description**                                                                                                                                        |
| -------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| AbnormalSecurity.inline_response_200_1.cases.caseId      | String   | A unique identifier for this case.                                                                                                                     |
| AbnormalSecurity.inline_response_200_1.cases.description | String   | Description of the severity level for this case.                                                                                                       |
| AbnormalSecurity.inline_response_200_1.pageNumber        | Number   | The current page number. Will not be be in the response if no filter query meter is passed in via the request.                                         |
| AbnormalSecurity.inline_response_200_1.nextpageNumber    | Number   | The next page number. Will not be included in the response if there are no more pages of data or if no filter query meter is passed in via the request |

#### Command Example

`!abnormal-security-list-abnormal-cases filter="lastModifiedTime gte 2020-12-01T01:01:01Z"`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "inline_response_200_1": {
            "cases": [
                {
                    "caseId": 1234,
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

> ### List of Cases
>
> ### Case IDs
>
> | caseId | description                |
> | ------ | -------------------------- |
> | 1234   | Potential Account Takeover |

### abnormal-security-list-threats

---

Get a list of threats

#### Base Command

`abnormal-security-list-threats`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                          | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| filter            | Value must be of the format `filter={FILTER KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ`. A `{FILTER KEY}` must be specified, and currently the only key that is supported for `/threats` is `receivedTime`. At least 1 of `gte`/`lte` must be specified, with a datetime string following the `YYYY-MM-DDTHH:MM:SSZ format`. | Optional     |
| page_size         | Number of threats that on in each page. Each page of data will have at most page_size threats. Has no effect if filter is not specified.                                                                                                                                                                                                 | Optional     |
| page_number       | 1-indexed page number to get a particular page of threats. Has no effect if filter is not specified.                                                                                                                                                                                                                                     | Optional     |
| mock-data         | Returns test data if set to `True`.                                                                                                                                                                                                                                                                                                      | Optional     |
| source            | Filters threats based on the source of detection.                                                                                                                                                                                                                                                                                        | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                                                                                                                                                                                                                                                                   | Optional     |

#### Context Output

| **Path**                                              | **Type** | **Description**                                                                                                                                        |
| ----------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| AbnormalSecurity.inline_response_200.threats.threatId | String   | An id which maps to a threat campaign. A threat campaign might be received by multiple users.                                                          |
| AbnormalSecurity.inline_response_200.pageNumber       | Number   | The current page number. Will not be be in the response if no filter query meter is passed in via the request.                                         |
| AbnormalSecurity.inline_response_200.nextpageNumber   | Number   | The next page number. Will not be included in the response if there are no more pages of data or if no filter query meter is passed in via the request |

#### Command Example

`!abnormal-security-list-threats filter="receivedTime gte 2020-12-01T01:01:01Z"`

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

> ### List of Threats
>
> ### Threat IDs
>
> | threatId                             |
> | ------------------------------------ |
> | 184712ab-6d8b-47b3-89d3-a314efef79e2 |

### abnormal-security-get-threat

---

Get details of a threat

#### Base Command

`abnormal-security-get-threat`

#### Input

| **Argument Name** | **Description**                                                                                                               | **Required** |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------ |
| threat_id         | A UUID representing a threat campaign. Full list of threat IDs can be obtained by first running the command to list a threat. | Required     |
| mock-data         | Returns test data if set to `True`.                                                                                           | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                                                        | Optional     |

#### Context Output

| **Path**                                                     | **Type** | **Description**                                                                       |
| ------------------------------------------------------------ | -------- | ------------------------------------------------------------------------------------- |
| AbnormalSecurity.ThreatDetails.threatId                      | String   | An id which maps to a threat campaign.                                                |
| AbnormalSecurity.ThreatDetails.messages.abxMessageId         | Number   | A unique identifier for an individual message within a threat \(i.e email campaign\). |
| AbnormalSecurity.ThreatDetails.messages.abxPortalUrl         | String   | The URL at which the specific message details are viewable.                           |
| AbnormalSecurity.ThreatDetails.messages.attachmentCount      | Number   | The number of attachments in the email.                                               |
| AbnormalSecurity.ThreatDetails.messages.attachmentNames      | Array    | List of the names of attachments in the email.                                        |
| AbnormalSecurity.ThreatDetails.messages.attackStrategy       | String   | The attack strategy used in the threat.                                               |
| AbnormalSecurity.ThreatDetails.messages.attackType           | String   | The type of threat the message represents.                                            |
| AbnormalSecurity.ThreatDetails.messages.attackVector         | String   | The medium used for the attack.                                                       |
| AbnormalSecurity.ThreatDetails.messages.attackedParty        | String   | The party that was targeted by the attack.                                            |
| AbnormalSecurity.ThreatDetails.messages.autoRemediated       | Boolean  | Whether the threat was automatically remediated.                                      |
| AbnormalSecurity.ThreatDetails.messages.fromAddress          | String   | The email address of the sender.                                                      |
| AbnormalSecurity.ThreatDetails.messages.fromName             | String   | The display name of the sender.                                                       |
| AbnormalSecurity.ThreatDetails.messages.impersonatedParty    | String   | The party, if any, that was impersonated in the attack.                               |
| AbnormalSecurity.ThreatDetails.messages.internetMessageId    | String   | The Internet Message ID, per RFC 822.                                                 |
| AbnormalSecurity.ThreatDetails.messages.isRead               | Boolean  | Whether the email has been read.                                                      |
| AbnormalSecurity.ThreatDetails.messages.postRemediated       | Boolean  | Whether the threat was remediated after landing in the user's mailbox.                |
| AbnormalSecurity.ThreatDetails.messages.receivedTime         | String   | The timestamp at which this message arrived.                                          |
| AbnormalSecurity.ThreatDetails.messages.recipientAddress     | String   | The email address of the user who actually received the message.                      |
| AbnormalSecurity.ThreatDetails.messages.remediationStatus    | String   | The status of remediation action.                                                     |
| AbnormalSecurity.ThreatDetails.messages.remediationTimestamp | String   | The timestamp at which the message was remediated.                                    |
| AbnormalSecurity.ThreatDetails.messages.sentTime             | String   | The timestamp at which this message was sent.                                         |
| AbnormalSecurity.ThreatDetails.messages.subject              | String   | The subject of the email.                                                             |
| AbnormalSecurity.ThreatDetails.messages.threatId             | String   | An id which maps to a threat campaign.                                                |
| AbnormalSecurity.ThreatDetails.messages.toAddresses          | Array    | All the email addresses to which the message was sent.                                |
| AbnormalSecurity.ThreatDetails.messages.ccEmails             | Array    | All the email addresses in CC.                                                        |
| AbnormalSecurity.ThreatDetails.messages.replyToEmails        | Array    | All the email addresses in the "Reply To" field.                                      |
| AbnormalSecurity.ThreatDetails.messages.returnPath           | String   | The path where information is returned to the attacker.                               |
| AbnormalSecurity.ThreatDetails.messages.senderDomain         | String   | The domain of the sender.                                                             |
| AbnormalSecurity.ThreatDetails.messages.senderIpAddress      | String   | The IP address of the sender.                                                         |
| AbnormalSecurity.ThreatDetails.messages.summaryInsights      | Array    | Summary insights into the threat's characteristics.                                   |
| AbnormalSecurity.ThreatDetails.messages.urlCount             | Number   | The number of URLs contained in the email.                                            |
| AbnormalSecurity.ThreatDetails.messages.urls                 | Array    | List of all URLs contained in the email.                                              |

#### Command Example

`!abnormal-security-get-threat threat_id=xwvutsrq-9pon-mlkj-i876-54321hgfedcba`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "ThreatDetails": {
            "messages": [
                {
                    "abxMessageId": 4551618356913732000,
                    "abxPortalUrl": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/4551618356913732076",
                    "attachmentCount": null,
                    "attachmentNames": ["attachment.pdf"],
                    "attackStrategy": "Name Impersonation",
                    "attackType": "Extortion",
                    "attackVector": "Text",
                    "attackedParty": "VIP",
                    "autoRemediated": true,
                    "ccEmails": ["cc@example.com"],
                    "fromAddress": "support@secure-reply.org",
                    "fromName": "",
                    "impersonatedParty": "None / Others",
                    "internetMessageId": "<5edfca1c.1c69fb81.4b055.8fd5@mx.google.com>",
                    "isRead": true,
                    "postRemediated": true,
                    "receivedTime": "2020-06-09T17:42:59Z",
                    "recipientAddress": "example@example.com",
                    "remediationTimestamp": "2020-06-09T17:42:59Z",
                    "replyToEmails": ["reply-to@example.com"],
                    "returnPath": "support@secure-reply.org",
                    "senderDomain": "",
                    "senderIpAddress": "100.101.102.103",
                    "sentTime": "2020-06-09T17:42:59Z",
                    "subject": "Phishing Email",
                    "summaryInsights": ["Bitcoin Topics", "Personal Information Theft", "Unusual Sender"],
                    "threatId": "184712ab-6d8b-47b3-89d3-a314efef79e2",
                    "toAddresses": "example@example.com, another@example.com",
                    "urlCount": 0,
                    "urls": ["https://www.google.com/"]
                }
            ],
            "threatId": "184712ab-6d8b-47b3-89d3-a314efef79e2"
        }
    }
}
```

#### Human Readable Output

> ### Messages in Threat 184712ab-6d8b-47b3-89d3-a314efef79e2
>
> | subject        | fromAddress              | toAddresses                              | recipientAddress    | receivedTime         | attackType | attackStrategy     | returnPath               | --  |
> | -------------- | ------------------------ | ---------------------------------------- | ------------------- | -------------------- | ---------- | ------------------ | ------------------------ | --- |
> | Phishing Email | support@secure-reply.org | example@example.com, another@example.com | example@example.com | 2020-06-09T17:42:59Z | Extortion  | Name Impersonation | support@secure-reply.org | etc |

### abnormal-security-get-abnormal-case

---

Get details of an Abnormal case

#### Base Command

`abnormal-security-get-abnormal-case`

#### Input

| **Argument Name** | **Description**                                                                                | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------- | ------------ |
| case_id           | A string representing the email case. Can be retrieved by first running command to list cases. | Required     |
| mock-data         | Returns test data if set to `True`.                                                            | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                         | Optional     |

#### Context Output

| **Path**                                              | **Type** | **Description**                                  |
| ----------------------------------------------------- | -------- | ------------------------------------------------ |
| AbnormalSecurity.AbnormalCaseDetails.caseId           | String   | A unique identifier for this case.               |
| AbnormalSecurity.AbnormalCaseDetails.severity         | String   | Description of the severity level for this case. |
| AbnormalSecurity.AbnormalCaseDetails.affectedEmployee | String   | Which employee this case pertains to.            |
| AbnormalSecurity.AbnormalCaseDetails.firstObserved    | String   | First time suspicious behavior was observed.     |

#### Command Example

`!abnormal-security-get-abnormal-case case_id=12805`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "AbnormalCaseDetails": {
            "affectedEmployee": "FirstName LastName",
            "analysis": "Mail Sent",
            "caseId": 1234,
            "case_status": "Action Required",
            "firstObserved": "2020-06-09T17:42:59Z",
            "remediation_status": "Not remediated",
            "severity": "Potential Account Takeover",
            "threatIds": ["184712ab-6d8b-47b3-89d3-a314efef79e2"]
        }
    }
}
```

#### Human Readable Output

> ### Details of Case 1234
>
> | caseId | severity                   | affectedEmployee   | firstObserved        | threatIds                            |
> | ------ | -------------------------- | ------------------ | -------------------- | ------------------------------------ |
> | 1234   | Potential Account Takeover | FirstName LastName | 2020-06-09T17:42:59Z | 184712ab-6d8b-47b3-89d3-a314efef79e2 |

### abnormal-security-get-abuse-mailbox-campaign

---

Get details of an Abuse Mailbox campaign

#### Base Command

`abnormal-security-get-abuse-mailbox-campaign`

#### Input

| **Argument Name** | **Description**                                                                                                              | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------ |
| campaign_id       | A UUID representing the abuse campaign id. Can be Can be retrieved by first running command to list abuse mailbox campaigns. | Required     |
| mock-data         | Returns test data if set to `True`.                                                                                          | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                                                       | Optional     |

#### Context Output

| **Path**                                        | **Type** | **Description**                                                  |
| ----------------------------------------------- | -------- | ---------------------------------------------------------------- |
| AbnormalSecurity.AbuseCampaign.campaignId       | String   | An id which maps to an abuse campaign.                           |
| AbnormalSecurity.AbuseCampaign.firstReported    | String   | Date abuse campaign was first reported.                          |
| AbnormalSecurity.AbuseCampaign.lastReported     | String   | Date abuse campaign was last reported.                           |
| AbnormalSecurity.AbuseCampaign.messageId        | String   | A unique identifier for the first message in the abuse campaign. |
| AbnormalSecurity.AbuseCampaign.subject          | String   | Subject of the first email in the abuse campaign.                |
| AbnormalSecurity.AbuseCampaign.fromName         | String   | The display name of the sender.                                  |
| AbnormalSecurity.AbuseCampaign.fromAddress      | String   | The email address of the sender.                                 |
| AbnormalSecurity.AbuseCampaign.recipientName    | String   | The email address of the recipient.                              |
| AbnormalSecurity.AbuseCampaign.recipientAddress | String   | The email address of the recipient.                              |
| AbnormalSecurity.AbuseCampaign.judgementStatus  | String   | Judgement status of message.                                     |
| AbnormalSecurity.AbuseCampaign.overallStatus    | String   | Overall status of message.                                       |
| AbnormalSecurity.AbuseCampaign.attackType       | String   | The type of threat the message represents.                       |

#### Command Example

`!abnormal-security-get-abuse-mailbox-campaign campaign_id=xwvutsrq-9pon-mlkj-i876-54321hgfedcba`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "AbuseCampaign": {
            "campaigns": {
                "attackType": "Attack Type: Spam",
                "campaignId": "fff51768-c446-34e1-97a8-9802c29c3ebd",
                "firstReported": "2020-11-11T13:11:40-08:00",
                "fromAddress": "example@example.com",
                "fromName": "Tom Dinkley",
                "judgementStatus": "Malicious",
                "lastReported": "2020-11-11T13:11:40-08:00",
                "messageId": "12345678910",
                "overallStatus": "Move attempted",
                "recipientAddress": "example_phisher@example.com",
                "recipientName": "Booker",
                "subject": "Fwd: This is spam"
            }
        }
    }
}
```

#### Human Readable Output

> ### Results
>
> | attackType        | campaignId                           | firstReported             | fromAddress         | fromName    | judgementStatus | lastReported              | messageId   | overallStatus  | recipientAddress            | recipientName | subject           |
> | ----------------- | ------------------------------------ | ------------------------- | ------------------- | ----------- | --------------- | ------------------------- | ----------- | -------------- | --------------------------- | ------------- | ----------------- |
> | Attack Type: Spam | fff51768-c446-34e1-97a8-9802c29c3ebd | 2020-11-11T13:11:40-08:00 | example@example.com | Tom Dinkley | Malicious       | 2020-11-11T13:11:40-08:00 | 12345678910 | Move attempted | example_phisher@example.com | Booker        | Fwd: This is spam |

### abnormal-security-get-employee-identity-analysis

---

Get employee identity analysis (Genome) data

#### Base Command

`abnormal-security-get-employee-identity-analysis`

#### Input

| **Argument Name** | **Description**                                              | **Required** |
| ----------------- | ------------------------------------------------------------ | ------------ |
| email_address     | Email address of the employee you want to retrieve data for. | Required     |
| mock-data         | Returns test data if set to `True`.                          | Optional     |

#### Context Output

| **Path**                                                | **Type** | **Description**                           |
| ------------------------------------------------------- | -------- | ----------------------------------------- |
| AbnormalSecurity.Employee.email                         | String   | Employee email                            |
| AbnormalSecurity.Employee.histograms.key                | String   | Genome key name                           |
| AbnormalSecurity.Employee.histograms.name               | String   | Genome title                              |
| AbnormalSecurity.Employee.histograms.description        | String   | Description of genome object              |
| AbnormalSecurity.Employee.histograms.values.value       | String   | Category value                            |
| AbnormalSecurity.Employee.histograms.values.percentage  | Number   | Ratio of this category relative to others |
| AbnormalSecurity.Employee.histograms.values.total_count | Number   | Number of occurences for this category    |

#### Command Example

`!abnormal-security-get-employee-identity-analysis email_address="test@test.com"`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "Employee": {
            "email": "test@test.com",
            "histograms": [
                {
                    "description": "Common IP addresses for user logins",
                    "key": "ip_address",
                    "name": "Common IP Addresses",
                    "values": [
                        {
                            "ratio": 0.25,
                            "raw_count": 12,
                            "text": "ip-address-0"
                        },
                        {
                            "ratio": 0.25,
                            "raw_count": 12,
                            "text": "ip-address-1"
                        },
                        {
                            "ratio": 0.25,
                            "raw_count": 12,
                            "text": "ip-address-2"
                        },
                        {
                            "ratio": 0.25,
                            "raw_count": 12,
                            "text": "ip-address-3"
                        }
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

> ### Analysis of test@test.com
>
> | description                         | key        | name                | values                                                                                                                                                                                                                                             |
> | ----------------------------------- | ---------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
> | Common IP addresses for user logins | ip_address | Common IP Addresses | {'text': 'ip-address-0', 'ratio': 0.25, 'raw_count': 12},<br/>{'text': 'ip-address-1', 'ratio': 0.25, 'raw_count': 12},<br/>{'text': 'ip-address-2', 'ratio': 0.25, 'raw_count': 12},<br/>{'text': 'ip-address-3', 'ratio': 0.25, 'raw_count': 12} |

### abnormal-security-get-employee-information

---

Get employee information

#### Base Command

`abnormal-security-get-employee-information`

#### Input

| **Argument Name** | **Description**                                              | **Required** |
| ----------------- | ------------------------------------------------------------ | ------------ |
| email_address     | Email address of the employee you want to retrieve data for. | Required     |
| mock-data         | Returns test data if set to `True`.                          | Optional     |

#### Context Output

| **Path**                          | **Type** | **Description**                         |
| --------------------------------- | -------- | --------------------------------------- |
| AbnormalSecurity.Employee.name    | String   | Name of the employee.                   |
| AbnormalSecurity.Employee.email   | String   | Email of the employee.                  |
| AbnormalSecurity.Employee.title   | String   | Job title of the employee.              |
| AbnormalSecurity.Employee.manager | String   | Email address of the employee's manager |

#### Command Example

`!abnormal-security-get-employee-information email_address="test@test.com"`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "Employee": {
            "email": "testemail@email.com",
            "manager": "testmanageremail@email.net",
            "name": "test_name",
            "title": "Test Operator"
        }
    }
}
```

#### Human Readable Output

> ### Results
>
> | email               | manager                    | name      | title         |
> | ------------------- | -------------------------- | --------- | ------------- |
> | testemail@email.com | testmanageremail@email.net | test_name | Test Operator |

### abnormal-security-get-employee-last-30-days-login-csv

---

Get employee login information for last 30 days in csv format

#### Base Command

`abnormal-security-get-employee-last-30-days-login-csv`

#### Input

| **Argument Name** | **Description**                                              | **Required** |
| ----------------- | ------------------------------------------------------------ | ------------ |
| email_address     | Email address of the employee you want to retrieve data for. | Required     |
| mock-data         | Returns test data if set to `True`.                          | Optional     |

#### Context Output

There is no context output for this command.

#### Command Example

`!abnormal-security-get-employee-last-30-days-login-csv email_address="test@test.com"`

#### Context Example

```json
{
    "File": {
        "EntryID": "2338@2ef16ace-2149-42b9-8b0f-fb7620ba7d44",
        "Extension": "csv",
        "Info": "csv",
        "MD5": "11afb4879c5026e25bd868dfcf23e811",
        "Name": "employee_login_info_30_days.csv",
        "SHA1": "345ea1d24b52c96baf6b0e4d892d13d4efcf666d",
        "SHA256": "12620e0f576f4d74603b1f542919a3e5199e61435ffd99bcd68c26e02ed9c693",
        "SHA512": "f0e788981ce70d9668100ae3f93d1f28660f0d8a9dfda02284a70f08ac14ca5a356872284f460d8fb7970791e314e0db4a6c84b0032c35046efce62368a00da5",
        "SSDeep": "12:uR2xCC56aHoW2IY3zg05Eg05ng05Eg05V:uROjHn2IY3v5i5T5i5V",
        "Size": 484,
        "Type": "ASCII text, with CRLF line terminators"
    }
}
```

### abnormal-security-get-latest-threat-intel-feed

---

DEPRECATED. Get the latest threat intel feed.

#### Base Command

`abnormal-security-get-latest-threat-intel-feed`

#### Input

| **Argument Name** | **Description**                     | **Required** |
| ----------------- | ----------------------------------- | ------------ |
| mock-data         | Returns test data if set to `True`. | Optional     |

#### Context Output

There is no context output for this command.

#### Command Example

`!abnormal-security-get-latest-threat-intel-feed`

#### Context Example

```json
{
    "File": {
        "EntryID": "2314@2ef16ace-2149-42b9-8b0f-fb7620ba7d44",
        "Extension": "json",
        "Info": "application/json",
        "MD5": "a00e919efc9e28f77b8f7b7523b1ffe8",
        "Name": "threat_intel_feed.json",
        "SHA1": "53bf3e6075f407b53c95d5dd2197b9be0dfa5ced",
        "SHA256": "f842e7f6795fba081f2046617fce662c050b5a3c64cac9501f23fa7576788429",
        "SHA512": "27af66eefb1ed7227b4f8ec1c663ac8ef47660bb34ffd1d5853a7a58e25caec68615c2e66bfbd66577749faa889894e792f53cab70a826818b4d627ad02bbb04",
        "SSDeep": "49152:dY0GiMq58ZVhOH+sZwFp+h/s0pH6VRRxIGFe7V3dCLtJ/W7H8nsIdL0E:u",
        "Size": 8007799,
        "Type": "ASCII text"
    }
}
```

### abnormal-security-manage-threat

---

Manage a Threat identified by Abnormal Security

#### Base Command

`abnormal-security-manage-threat`

#### Input

| **Argument Name** | **Description**                                                                                                               | **Required** |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------ |
| threat_id         | A UUID representing a threat campaign. Full list of threat IDs can be obtained by first running the command to list a threat. | Required     |
| action            | Action to perform on threat.                                                                                                  | Required     |
| mock-data         | Returns test data if set to `True`.                                                                                           | Optional     |

#### Context Output

| **Path**                                        | **Type** | **Description**                 |
| ----------------------------------------------- | -------- | ------------------------------- |
| AbnormalSecurity.ThreatManageResults.action_id  | String   | ID of the action taken          |
| AbnormalSecurity.ThreatManageResults.status_url | String   | URL of the status of the action |

#### Command Example

`!abnormal-security-manage-threat threat_id=xwvutsrq-9pon-mlkj-i876-54321hgfedcba action=remediate`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "ThreatManageResults": {
            "action_id": "a33a212a-89ff-461f-be34-ea52aff44a73",
            "status_url": "https://api.abnormalplatform.com/v1/threats/184712ab-6d8b-47b3-89d3-a314efef79e2/actions/a33a212a-89ff-461f-be34-ea52aff44a73"
        }
    }
}
```

#### Human Readable Output

> ### Results
>
> | action_id                            | status_url                                                                                                                    |
> | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
> | a33a212a-89ff-461f-be34-ea52aff44a73 | https://api.abnormalplatform.com/v1/threats/184712ab-6d8b-47b3-89d3-a314efef79e2/actions/a33a212a-89ff-461f-be34-ea52aff44a73 |

### abnormal-security-manage-abnormal-case

---

Manage an Abnormal Case.

#### Base Command

`abnormal-security-manage-abnormal-case`

#### Input

| **Argument Name** | **Description**                                                                                | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------- | ------------ |
| case_id           | A string representing the email case. Can be retrieved by first running command to list cases. | Required     |
| action            | Action to perform on case.                                                                     | Required     |
| mock-data         | Returns test data if set to `True`.                                                            | Optional     |

#### Context Output

| **Path**                                      | **Type** | **Description**                 |
| --------------------------------------------- | -------- | ------------------------------- |
| AbnormalSecurity.CaseManageResults.action_id  | String   | ID of the action taken          |
| AbnormalSecurity.CaseManageResults.status_url | String   | URL of the status of the action |

#### Command Example

`!abnormal-security-manage-abnormal-case case_id=12805 action=action_required`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "CaseManageResults": {
            "action_id": "61e76395-40d3-4d78-b6a8-8b17634d0f5b",
            "status_url": "https://api.abnormalplatform.com/v1/cases/1234/actions/61e76395-40d3-4d78-b6a8-8b17634d0f5b"
        }
    }
}
```

#### Human Readable Output

> ### Results
>
> | action_id                            | status_url                                                                                  |
> | ------------------------------------ | ------------------------------------------------------------------------------------------- |
> | 61e76395-40d3-4d78-b6a8-8b17634d0f5b | https://api.abnormalplatform.com/v1/cases/1234/actions/61e76395-40d3-4d78-b6a8-8b17634d0f5b |

### abnormal-security-get-case-analysis-and-timeline

---

Provides the analysis and timeline details of a case

#### Base Command

`abnormal-security-get-case-analysis-and-timeline`

#### Input

| **Argument Name** | **Description**                                                                                | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------- | ------------ |
| case_id           | A string representing the email case. Can be retrieved by first running command to list cases. | Required     |
| mock-data         | Returns test data if set to `True`.                                                            | Optional     |
| subtenant         | Subtenant of the user (if applicable).                                                         | Optional     |

#### Context Output

| **Path**                                                    | **Type** | **Description**                                                  |
| ----------------------------------------------------------- | -------- | ---------------------------------------------------------------- |
| AbnormalSecurity.CaseAnalysis.insights.signal               | String   | Insight signal or highlight of a case                            |
| AbnormalSecurity.CaseAnalysis.insights.description          | String   | Description of insight signal or highlight                       |
| AbnormalSecurity.CaseAnalysis.eventTimeline.event_timestamp | String   | Time when event occurred                                         |
| AbnormalSecurity.CaseAnalysis.eventTimeline.category        | String   | Type of event                                                    |
| AbnormalSecurity.CaseAnalysis.eventTimeline.title           | String   | Title of the event                                               |
| AbnormalSecurity.CaseAnalysis.eventTimeline.ip_address      | String   | IP Address where user accessed mail from                         |
| AbnormalSecurity.CaseAnalysis.eventTimeline.field_labels    | Unknown  | Analysis labels associated with the fields in the timeline event |

#### Command Example

`!abnormal-security-get-case-analysis-and-timeline case_id=12345`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "CaseAnalysis": {
            "eventTimeline": [
                {
                    "category": "Risk Event",
                    "description": "Impossible Travel Event was observed for test@lamronba.com.",
                    "event_timestamp": "2021-07-14T22:41:54Z",
                    "ip_address": "127.0.0.1",
                    "location": {
                        "city": "Aldie",
                        "country": "US",
                        "state": "Virginia"
                    },
                    "prev_location": {
                        "city": "Atherton",
                        "country": "US",
                        "state": "California"
                    },
                    "title": "Impossible Travel"
                },
                {
                    "category": "Mail Rule",
                    "condition": "hasNoCondition",
                    "event_timestamp": "2021-07-14T22:41:54Z",
                    "flagging_detectors": "DELETE_ALL",
                    "rule_name": "Swag Voice Note",
                    "title": "Mail Rule Change"
                },
                {
                    "category": "Mail Sent",
                    "event_timestamp": "2021-07-14T22:41:54Z",
                    "recipient": "Recipient Name",
                    "sender": "test@lamronba.com",
                    "subject": "Spoof email subject",
                    "title": "Unusual Correspondence"
                },
                {
                    "application": "Microsoft Office 365 Portal",
                    "browser": "Chrome 79.0.3453",
                    "category": "Sign In",
                    "description": "Suspicious Failed Sign In Attempt for test@lamronba.com",
                    "device_trust_type": "None",
                    "event_timestamp": "2021-07-14T22:41:54Z",
                    "field_labels": {
                        "ip_address": ["rare", "proxy"],
                        "operating_system": ["legacy"]
                    },
                    "ip_address": "127.0.0.1",
                    "isp": "NGCOM",
                    "location": {
                        "country": "Ireland"
                    },
                    "operating_system": "Windows XP",
                    "protocol": "Browser",
                    "title": "Suspicious Failed Sign In Attempt"
                }
            ],
            "insights": [
                {
                    "description": "There was a signin into test@lamronba.com from a location frequently used to launch attacks.",
                    "signal": "Risky Location"
                }
            ]
        }
    }
}
```

#### Human Readable Output

> ### Insights for 12345
>
> | signal         | description                                                                                  |
> | -------------- | -------------------------------------------------------------------------------------------- |
> | Risky Location | There was a signin into test@lamronba.com from a location frequently used to launch attacks. |
>
> ### Event Timeline for
>
> | event_timestamp      | category   | title                             | field_labels                                             | ip_address | description                                                 | location                                        | sender            | subject             | title                             | rule_name       |
> | -------------------- | ---------- | --------------------------------- | -------------------------------------------------------- | ---------- | ----------------------------------------------------------- | ----------------------------------------------- | ----------------- | ------------------- | --------------------------------- | --------------- |
> | 2021-07-14T22:41:54Z | Risk Event | Impossible Travel                 |                                                          | 127.0.0.1  | Impossible Travel Event was observed for test@lamronba.com. | city: Aldie<br/>state: Virginia<br/>country: US |                   |                     | Impossible Travel                 |                 |
> | 2021-07-14T22:41:54Z | Mail Rule  | Mail Rule Change                  |                                                          |            |                                                             |                                                 |                   |                     | Mail Rule Change                  | Swag Voice Note |
> | 2021-07-14T22:41:54Z | Mail Sent  | Unusual Correspondence            |                                                          |            |                                                             |                                                 | test@lamronba.com | Spoof email subject | Unusual Correspondence            |                 |
> | 2021-07-14T22:41:54Z | Sign In    | Suspicious Failed Sign In Attempt | ip_address: rare,<br/>proxy<br/>operating_system: legacy | 127.0.0.1  | Suspicious Failed Sign In Attempt for test@lamronba.com     | country: Ireland                                |                   |                     | Suspicious Failed Sign In Attempt |                 |

### [Deprecated] abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement

---

Submit an Inquiry to request a report on misjudgement by Abnormal Security

#### Base Command

`abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement`

#### Input

| **Argument Name** | **Description**                     | **Required** |
| ----------------- | ----------------------------------- | ------------ |
| mock-data         | Returns test data if set to `True`. | Optional     |
| reporter          | Email of the reporter.              | Required     |
| report_type       | Type of misjudgement reported.      | Required     |

#### Context Output

| **Path**                              | **Type** | **Description**              |
| ------------------------------------- | -------- | ---------------------------- |
| AbnormalSecurity.SubmitInquiry.detail | String   | Confirmation of inquiry sent |

#### Command Example

`!abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement reporter=abc@def.com report_type=false-positive`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "SubmitInquiry": {
            "detail": "Thank you for your feedback! We have sent your inquiry to our support staff."
        }
    }
}
```

#### Human Readable Output

> ### Results
>
> | detail                                                                       |
> | ---------------------------------------------------------------------------- |
> | Thank you for your feedback! We have sent your inquiry to our support staff. |

### abnormal-security-submit-false-negative-report

---

Submit a False Negative Report

#### Base Command

`abnormal-security-submit-false-negative-report`

#### Input

| **Argument Name** | **Description**                 | **Required** |
| ----------------- | ------------------------------- | ------------ |
| sender_email      | Email address of the sender.    | Required     |
| recipient_email   | Email address of the recipient. | Required     |
| subject           | Email subject.                  | Required     |

#### Command Example

`!abnormal-security-submit-false-negative-report recipient_email=abc@def.com sender_email=def@def.com subject=hello`

#### Human Readable Output

> ### Results
>
> | detail                                                                       |
> | ---------------------------------------------------------------------------- |
> | Thank you for your feedback! We have sent your inquiry to our support staff. |

### abnormal-security-submit-false-positive-report

---

Submit a False Positive Report

#### Base Command

`abnormal-security-submit-false-positive-report`

#### Input

| **Argument Name** | **Description**                                    | **Required** |
| ----------------- | -------------------------------------------------- | ------------ |
| portal_link       | URL link of threat log in abnormal security portal | Required     |

#### Command Example

`!abnormal-security-submit-false-positive-report portal_link=https://portal.abnormalsecurity.com/home/threat-center/remediation-history/123455667`

#### Human Readable Output

> ### Results
>
> | detail                                                                       |
> | ---------------------------------------------------------------------------- |
> | Thank you for your feedback! We have sent your inquiry to our support staff. |

### abnormal-security-list-vendors

---

Get a list of vendors

#### Base Command

`abnormal-security-list-vendors`

#### Input

| **Argument Name** | **Description**                                                                                                                           | **Required** |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| page_size         | Number of vendors that are on each page. Each page of data will have at most page_size vendors. Has no effect if filter is not specified. | Optional     |
| page_number       | 1-indexed page number to get a particular page of vendors. Has no effect if filter is not specified.                                      | Optional     |

#### Context Output

| **Path**                                  | **Type** | **Description**           |
| ----------------------------------------- | -------- | ------------------------- |
| AbnormalSecurity.VendorsList              | Unknown  | List of vendors.          |
| AbnormalSecurity.VendorsList.vendorDomain | String   | The domain of the vendor. |

#### Command Example

`!abnormal-security-list-vendors`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "VendorsList": [
            {
                "vendorDomain": "test-domain-1.com"
            },
            {
                "vendorDomain": "test-domain-2.com"
            },
            {
                "vendorDomain": "test-domain-2.com"
            }
        ]
    }
}
```

#### Human Readable Output

> ### List of Vendors
>
> ### Vendor Domains
>
> | vendorDomain      |
> | ----------------- |
> | test-domain-1.com |

### abnormal-security-get-vendor-details

---

Get details of a vendor

#### Base Command

`abnormal-security-get-vendor-details`

#### Input

| **Argument Name** | **Description**                                                                                                         | **Required** |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------ |
| vendor_domain     | The domain name of the vendor in question. It should be formatted as a fully qualified domain name (e.g., example.com). | Required     |

#### Context Output

| **Path**                                         | **Type** | **Description**                                  |
| ------------------------------------------------ | -------- | ------------------------------------------------ |
| AbnormalSecurity.VendorDetails.vendorDomain      | String   | The domain name of the vendor                    |
| AbnormalSecurity.VendorDetails.riskLevel         | String   | The risk level associated with the vendor.       |
| AbnormalSecurity.VendorDetails.vendorContacts    | Unknown  | List of contacts related to the vendor.          |
| AbnormalSecurity.VendorDetails.companyContacts   | Unknown  | List of contacts related to the company.         |
| AbnormalSecurity.VendorDetails.vendorCountries   | Unknown  | List of countries associated with the vendor.    |
| AbnormalSecurity.VendorDetails.analysis          | Unknown  | List of analyses associated with the vendor.     |
| AbnormalSecurity.VendorDetails.vendorIpAddresses | Unknown  | List of IP addresses associated with the vendor. |

#### Command Example

`!abnormal-security-get-vendor-details vendor_domain="test-domain-1.com"`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "VendorDetails": {
            "vendorDomain": "test-domain-1.com",
            "riskLevel": "High",
            "vendorContacts": ["john.doe@test-domain-1.com"],
            "companyContacts": ["john.doe@test-domain-2.com", "jane.doe@test-domain-2.com"],
            "vendorCountries": ["USA"],
            "analysis": ["Vendor Compromise Seen in Abnormal Community"],
            "vendorIpAddresses": ["192.158. 1.38"]
        }
    }
}
```

#### Human Readable Output

> ### Vendor Domain Details
>
> | vendorDomain      | riskLevel | vendorContacts             | companyContacts                                        | vendorCountries | analysis                                     | vendorIpAddresses |
> | ----------------- | --------- | -------------------------- | ------------------------------------------------------ | --------------- | -------------------------------------------- | ----------------- |
> | test-domain-1.com | High      | john.doe@test-domain-1.com | john.doe@test-domain-2.com, jane.doe@test-domain-2.com | USA             | Vendor Compromise Seen in Abnormal Community | 192.158.1.38      |

### abnormal-security-get-vendor-activity

# <<<<<<< HEAD

---

Get details of a vendor

> > > > > > > 52b3eaef7e (validating files)

---

Get details of a vendor

#### Base Command

`abnormal-security-get-vendor-activity`

#### Input

| **Argument Name** | **Description**                                                                                                         | **Required** |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------ |
| vendor_domain     | The domain name of the vendor in question. It should be formatted as a fully qualified domain name (e.g., example.com). | Required     |

#### Context Output

| **Path**                                                       | **Type** | **Description**                                              |
| -------------------------------------------------------------- | -------- | ------------------------------------------------------------ |
| AbnormalSecurity.VendorActivity.eventTimeline                  | Unknown  | Event timeline for the vendor.                               |
| AbnormalSecurity.VendorActivity.eventTimeline.eventTimestamp   | String   | Timestamp of the event in the vendor's activity timeline.    |
| AbnormalSecurity.VendorActivity.eventTimeline.eventType        | String   | Type of event in the vendor's activity timeline.             |
| AbnormalSecurity.VendorActivity.eventTimeline.suspiciousDomain | String   | Suspicious domain involved in the event.                     |
| AbnormalSecurity.VendorActivity.eventTimeline.domainIp         | String   | IP address of the suspicious domain.                         |
| AbnormalSecurity.VendorActivity.eventTimeline.ipGeolocation    | String   | Geolocation of the IP address.                               |
| AbnormalSecurity.VendorActivity.eventTimeline.attackGoal       | String   | The goal of the attack.                                      |
| AbnormalSecurity.VendorActivity.eventTimeline.actionTaken      | String   | Action taken in response to the event.                       |
| AbnormalSecurity.VendorActivity.eventTimeline.hasEngagement    | Boolean  | Indicates whether the event involved any form of engagement. |
| AbnormalSecurity.VendorActivity.eventTimeline.recipient        | Unknown  | The recipient targeted by the event, if applicable.          |
| AbnormalSecurity.VendorActivity.eventTimeline.threatId         | String   | Unique identifier for the threat.                            |

#### Command Example

`!abnormal-security-get-vendor-activity vendor_domain="test-domain-1.com"`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "VendorActivity": {
            "eventTimeline": [
                {
                    "eventTimestamp": "2023-07-28T16:20:05Z",
                    "eventType": "Federated Signal",
                    "suspiciousDomain": "test@test-domain.com",
                    "domainIp": "192.158.1.38",
                    "ipGeolocation": null,
                    "attackGoal": "Spam",
                    "actionTaken": "Remediation Triggered",
                    "hasEngagement": false,
                    "recipient": "jane@doe.com",
                    "threatId": "184712ab-6d8b-47b3-89d3-a314efef79e2"
                }
            ]
        }
    }
}
```

#### Human Readable Output

> ### Vendor Activity
>
> | eventTimestamp       | eventType        | suspiciousDomain            | domainIp     | ipGeolocation | attackGoal | actionTaken           | hasEngagement | recipient    | threatId                             |
> | -------------------- | ---------------- | --------------------------- | ------------ | ------------- | ---------- | --------------------- | ------------- | ------------ | ------------------------------------ |
> | 2023-07-28T16:20:05Z | Federated Signal | Signal test@test-domain.com | 192.158.1.38 | null          | Spam       | Remediation Triggered | false         | jane@doe.com | 184712ab-6d8b-47b3-89d3-a314efef79e2 |

### abnormal-security-list-vendor-cases

---

Get a list of vendor cases

#### Base Command

`!abnormal-security-list-vendor-cases`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                          | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| filter            | Value must be of the format `filter={FILTER KEY} gte YYYY-MM-DDTHH:MM:SSZ lte YYYY-MM-DDTHH:MM:SSZ`. A `{FILTER KEY}` must be specified, and currently the only keys that are supported are `firstObservedTime` and `lastModifiedTime`. At least 1 of `gte`/`lte` must be specified, with a datetime string following the `YYYY-MM-DDTHH:MM:SSZ` format. | Optional     |
| page_size         | Number of cases that are on each page.                                                                                                                                                                                                                                                                                                                   | Optional     |
| page_number       | 1-indexed page number to get a particular page of cases.                                                                                                                                                                                                                                                                                                 | Optional     |

#### Context Output

| **Path**                                  | **Type** | **Description**                    |
| ----------------------------------------- | -------- | ---------------------------------- |
| AbnormalSecurity.VendorCases              | Unknown  | List of vendor cases.              |
| AbnormalSecurity.VendorCases.vendorCaseId | Number   | The identifier of the vendor case. |

#### Command Example

`!abnormal-security-list-vendor-cases filter="lastModifiedTime gte 2020-12-01T01:01:01Z"`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "VendorCases": [
            {
                "vendorCaseId": 123
            },
            {
                "vendorCaseId": 456
            },
            {
                "vendorCaseId": 789
            }
        ]
    }
}
```

#### Human Readable Output

> ### List of Cases
>
> ### Vendor Case IDs
>
> | vendorCaseId |
> | ------------ |
> | 123          |

### abnormal-security-get-vendor-case-details

---

Get details of a vendor case

#### Base Command

`!abnormal-security-get-vendor-case-details`

#### Input

| **Argument Name** | **Description**                                                                                | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------- | ------------ |
| case_id           | A string representing the email case. Can be retrieved by first running command to list cases. | Required     |
| subtenant         | Subtenant of the user (if applicable).                                                         | Optional     |

#### Context Output

| **Path**                                             | **Type** | **Description**                                |
| ---------------------------------------------------- | -------- | ---------------------------------------------- |
| AbnormalSecurity.VendorCaseDetails.vendorCaseId      | String   | The identifier of the vendor case.             |
| AbnormalSecurity.VendorCaseDetails.vendorDomain      | String   | The vendor domain associated with the case.    |
| AbnormalSecurity.VendorCaseDetails.firstObservedTime | String   | The time the vendor case was first observed.   |
| AbnormalSecurity.VendorCaseDetails.lastModifiedTime  | String   | The last time the vendor case was modified.    |
| AbnormalSecurity.VendorCaseDetails.insights          | Unknown  | List of insights related to the vendor case.   |
| AbnormalSecurity.VendorCaseDetails.timeline          | Unknown  | Timeline of events related to the vendor case. |

#### Command Example

`!abnormal-security-get-vendor-case-details case_id=123`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "AbnormalCaseDetails": {
            "vendorCaseId": 123,
            "vendorDomain": "some-domain.com",
            "firstObservedTime": "2022-04-04T21:12:14Z",
            "lastModifiedTime": "2022-04-05T14:40:11Z",
            "insights": [
                {
                    "highlight": "Inconsistent Sender Domain Registrars",
                    "description": "The suspicious sending domain, \"some-domain.com\", was registered in \"City, United States\" to \"unknown\" on 2022-02-07 with registrar \"ABCD\". The legitimate domain for \"some-domain.com\", was registered through \"Test, LLC\" in \"City, United States\" on 1999-12-02."
                },
                {
                    "highlight": "Look-a-like Sender Domain",
                    "description": "The sending domain of this message, \"some-domain.com\", is attempting to impersonate the legitimate domain of \"some-domain.com\"."
                },
                {
                    "highlight": "Young Sender Domain",
                    "description": "The sender domain \"some-domain.com\" was 65 days old when the first engagement in this case was observed, a suspicious signal for a financial email conversation."
                }
            ],
            "timeline": [
                {
                    "eventTimestamp": "2022-04-04T21:12:14Z",
                    "senderAddress": "john-doe@some-domain.com",
                    "recipientAddress": "jane.doe@some-other-domain.com",
                    "subject": "Important Notice",
                    "markedAs": "Malicious",
                    "threatId": 1234
                },
                {
                    "eventTimestamp": "2022-04-04T21:12:14Z",
                    "senderAddress": "jand-doe@some-domain.com",
                    "recipientAddress": "john@some-other-domain.com",
                    "subject": "Important Notice",
                    "markedAs": "Malicious",
                    "threatId": 12345
                }
            ]
        }
    }
}
```

#### Human Readable Output

> ### Case Details
>
> | vendorCaseId | vendorDomain    | firstObservedTime    | lastModifiedTime     | insights                                                                                                                                                                                                                                                                                                                                                     | timeline                                                                                                                                                                                                            |
> | ------------ | --------------- | -------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
> | 123          | some-domain.com | 2022-04-04T21:12:14Z | 2022-04-05T14:40:11Z | {"highlight": "Inconsistent Sender Domain Registrars","description": "The suspicious sending domain, \"some-domain.com\", was registered in \"City, United States\" to \"unknown\" on 2022-02-07 with registrar \"ABCD\". The legitimate domain for \"some-domain.com\", was registered through \"Test, LLC\" in \"City, United States\" on 1999-12-02."}... | {"eventTimestamp": "2022-04-04T21:12:14Z","senderAddress": "john-doe@some-domain.com","recipientAddress": "jane.doe@some-other-domain.com","subject": "Important Notice","markedAs": "Malicious","threatId": 123}.. |

### abnormal-security-list-unanalyzed-abuse-mailbox-campaigns

---

Get a list of unanalyzed Abuse Mailbox campaigns

#### Base Command

`abnormal-security-list-unanalyzed-abuse-mailbox-campaigns`

#### Input

| **Argument Name** | **Description**                                                                | **Required** |
| ----------------- | ------------------------------------------------------------------------------ | ------------ |
| start             | The start time for retrieving the list of unanalyzed abuse mailbox campaigns.. | Optional     |
| end               | The end time for retrieving the list of unanalyzed abuse mailbox campaigns.    | Optional     |

#### Context Output

| **Path**                                                              | **Type** | **Description**                          |
| --------------------------------------------------------------------- | -------- | ---------------------------------------- |
| AbnormalSecurity.UnanalyzedAbuseCampaigns.results.abx_message_id      | Number   | An id which maps to an abuse campaign.   |
| AbnormalSecurity.UnanalyzedAbuseCampaigns.results.recipient.name      | String   | The name of the recipient.               |
| AbnormalSecurity.UnanalyzedAbuseCampaigns.results.recipient.email     | String   | The email address of the recipient.      |
| AbnormalSecurity.UnanalyzedAbuseCampaigns.results.reported_datetime   | String   | The datetime the report was made.        |
| AbnormalSecurity.UnanalyzedAbuseCampaigns.results.reporter.email      | String   | The email address of the reporter.       |
| AbnormalSecurity.UnanalyzedAbuseCampaigns.results.reporter.name       | String   | The name of the reporter.                |
| AbnormalSecurity.UnanalyzedAbuseCampaigns.results.subject             | String   | The subject of the message.              |
| AbnormalSecurity.UnanalyzedAbuseCampaigns.results.not_analyzed_reason | String   | The reason the message was not analyzed. |

#### Command Example

`!abnormal-security-list-unanalyzed-abuse-mailbox-campaigns`

#### Context Example

```json
{
    "AbnormalSecurity": {
        "AbuseCampaign": {
            "results": [
                {
                    "abx_message_id": 123456789,
                    "recipient": {
                        "name": "John Doe",
                        "email": "john.doe@some-domain.com"
                    },
                    "reported_datetime": "2023-06-15T00:17:31Z",
                    "reporter": {
                        "email": "info@some-domain.com",
                        "name": "Support"
                    },
                    "subject": "URGENT",
                    "not_analyzed_reason": "INVALID_SUBMISSION"
                },
                {
                    "abx_message_id": 987654321,
                    "recipient": {
                        "name": "Jane Doe",
                        "email": "jane.doe@some-domain.com"
                    },
                    "reported_datetime": "2023-06-14T06:23:31Z",
                    "reporter": {
                        "email": "info@some-domain.com",
                        "name": "support"
                    },
                    "subject": "Hello",
                    "not_analyzed_reason": "INVALID_SUBMISSION"
                }
            ]
        }
    }
}
```

#### Human Readable Output

> ### Unanalyzed Abuse Mailbox Campaigns
>
> | abx_message_id | recipient                                      | reported_datetime    | reporter                                   | subject | not_analyzed_reason |
> | -------------- | ---------------------------------------------- | -------------------- | ------------------------------------------ | ------- | ------------------- |
> | 123456789      | name: John Doe email: john.doe@some-domain.com | 2023-06-15T00:17:31Z | email : info@some-domain.com name: Support | URGENT  | INVALID_SUBMISSION  |