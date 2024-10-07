The Cofense Vision integration provides commands to initiate advanced search jobs to hunt suspicious emails matching IOCs. It also contains commands to quarantine emails, download messages and their attachments, and aids to manage IOCs in the local repository to keep up with upcoming emerging threats.
This integration was integrated and tested with version 4 of Cofense Vision and version 1 of Cofense IOC Repository.

## Configure Cofense Vision in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Server URL to connect to Cofense Vision. | True |
| Client ID |  | True |
| Client Secret |  | True |
| Threat levels to be marked as Good | Mapping of Cofense Vision threat level to XSOAR DbotScore.<br/>For 'Good', DbotScore will be 1 and default threat level value is 'low'.<br/>Comma separated values are supported. | False |
| Threat levels to be marked as Suspicious | Mapping of Cofense Vision threat level to XSOAR DbotScore.<br/>For 'Suspicious', DbotScore will be 2 and default threat level values are 'suspicious', 'moderate', 'substantial'.<br/>Comma separated values are supported. | False |
| Threat levels to be marked as Bad | Mapping of Cofense Vision threat level to XSOAR DbotScore.<br/>For 'Bad', DbotScore will be 3 and default threat level values are 'malicious', 'severe', 'critical', 'high'.<br/>Comma separated values are supported. | False |
| Trust any certificate (not secure) | Indicates whether to allow connections without verifying SSL certificate's validity. | False |
| Use system proxy settings | Indicates whether to use XSOAR's system proxy settings to connect to the API. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cofense-message-token-get
***
Retrieves a one-time token that can be used to get an email's content.


#### Base Command

`cofense-message-token-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| internet_message_id | Unique identifier of the email, enclosed in angle brackets.<br/><br/>Example: &lt;AC6CAE11-779E-4044-BB25-110171AB0301@example.com&gt;<br/><br/>Note: Users can get the ID by executing the "cofense-message-search-results-get" command. | Required | 
| recipient_address | Email address of the recipient of the email.<br/><br/>Note: The email address can be a carbon copy (Cc) or blind<br/>carbon copy (Bcc) recipient but cannot be a shared mailbox or a<br/>distribution list.<br/><br/>Note: Users can get the recipient address by executing the "cofense-message-search-results-get" command. | Required | 
| password | Password to protect the zip file containing the email. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Message.token | String | One-time token to access an email content. | 
| Cofense.Message.internetMessageId | String | ID of an email assigned by the message transfer agent. | 
| Cofense.Message.recipients.address | String | Email address of the recipient. | 

#### Command example
```!cofense-message-token-get internet_message_id="<1216208547.160.1658930322668@6d14a4fa9032>" recipient_address="abc@example.com"```
#### Context Example
```json
{
    "Cofense": {
        "Message": {
            "internetMessageId": "<1216208547.160.1658930322668@6d14a4fa9032>",
            "recipient": {
                "address": "abc@example.com"
            },
            "token": "de7475a4-3802-46c1-8e4c-2665912445c0"
        }
    }
}
```

#### Human Readable Output

>### One-time token:
>|Internet Message ID|Recipient's Address|Token|
>|---|---|---|
>| <1216208547.160.1658930322668@6d14a4fa9032\> | abc@example.com | de7475a4\-3802\-46c1\-8e4c\-2665912445c0 |


### cofense-message-metadata-get
***
Retrieves the full content of a message that matches the specified Internet message ID and recipient email address of an email.


#### Base Command

`cofense-message-metadata-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| internet_message_id | Unique identifier of the email, enclosed in angle brackets.<br/><br/>Example: &lt;AC6CAE11-779E-4044-BB25-110171AB0301@example.com&gt;<br/><br/>Note: Users can get the internet message ID by executing the "cofense-message-search-results-get" command. | Required | 
| recipient_address | Email address of the recipient of an email. The email address can be a <br/>carbon copy (Cc) or blind carbon copy (Bcc) recipient but cannot be a <br/>shared mailbox or a distribution list.<br/><br/>Note: Users can get the recipient address by executing the "cofense-message-search-results-get" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Message.id | Number | ID of the message in cofense vision. | 
| Cofense.Message.storageUri | String | Storage URI of an email. | 
| Cofense.Message.subject | String | Subject of the email. | 
| Cofense.Message.receivedOn | Date | Date and time an email was received by the recipient. | 
| Cofense.Message.sentOn | Date | Date and time an email was sent to the recipient. | 
| Cofense.Message.deliveredOn | Date | Date and time an email was delivered to the recipient. | 
| Cofense.Message.processedOn | Date | Date and time cofense vision ingested the email. | 
| Cofense.Message.textBody | String | Body of an email in text format. | 
| Cofense.Message.htmlBody | String | Body of an email in HTML format. | 
| Cofense.Message.md5 | String | MD5 hash of the message. | 
| Cofense.Message.sha1 | String | SHA1 hash of the message. | 
| Cofense.Message.sha256 | String | SHA256 hash of the message. | 
| Cofense.Message.internetMessageId | String | ID of an email assigned by the message transfer agent. | 
| Cofense.Message.from.id | Number | ID of the sender. | 
| Cofense.Message.from.personal | String | Personal email of the sender. | 
| Cofense.Message.from.address | String | An email address of the sender. | 
| Cofense.Message.headers.name | String | The name of the key in the header. | 
| Cofense.Message.headers.value | String | The value of the key in the header. | 
| Cofense.Message.recipients.id | Number | ID of the recipient. | 
| Cofense.Message.recipients.personal | String | Personal email of the recipient. | 
| Cofense.Message.recipients.address | String | Email address of the recipient. | 
| Cofense.Message.recipients.recipientType | String | Type of the recipient. | 
| Cofense.Message.attachments.size | Number | The size of the attachment file. | 
| Cofense.Message.attachments.filename | String | The name of the attachment file. | 
| Cofense.Message.attachments.contentType | String | The content type present in the header. | 
| Cofense.Message.attachments.detectedContentType | String | The detected content type of the attachment. | 
| Cofense.Message.attachments.md5 | String | The MD5 hash of the attachment. | 
| Cofense.Message.attachments.sha256 | String | The SHA256 hash of the attachment. | 
| Cofense.Message.attachments.id | Number | The ID of the attachment. | 
| Cofense.Message.matchingIOCs | Unknown | MD5 hash of one or more matching IOCs. | 
| Cofense.Message.matchingSources | Unknown | One or more matching IOC sources. | 

#### Command example
```!cofense-message-metadata-get internet_message_id="<1216208547.160.1658930322668@6d14a4fa9032>" recipient_address="abc@example.com"```
#### Context Example
```json
{
    "Cofense": {
        "Message": {
            "attachments": [
                {
                    "contentType": "text/plain",
                    "detectedContentType": "text/plain",
                    "filename": "fileNum-Thread[mailer-011,5,main]-text-file-163.txt",
                    "id": 1673289,
                    "md5": "3d0e1d68f12afee22ae3e79e01027c7a",
                    "sha256": "ca68f5eecd5822783911ed392fbff3c171d3a1854c0f992364d038ee447f8ac3",
                    "size": 59173
                },
                {
                    "contentType": "application/zip",
                    "detectedContentType": "application/zip",
                    "filename": "fileNum-Thread[mailer-011,5,main]-text-file-146.txt.zip",
                    "id": 1673290,
                    "md5": "5c602ca45faac3bb128a5ecbf977f9f1",
                    "sha256": "6018b7cc402e6368d4542c0f6c129a99e35c80ae9001ec338e7621df2f8ac51f",
                    "size": 14563
                },
                {
                    "detectedContentType": "text/plain",
                    "filename": "text-file-146.txt",
                    "id": 1673291,
                    "md5": "c5aa88f949574a0a5e75a795dc507da7",
                    "sha256": "d3a070977ae0ae561bae2215526c187d5c46c54dd8899eefb8fe21ed0e6c1303",
                    "size": 27842
                }
            ],
            "from": [
                {
                    "address": "abc@example.com",
                    "id": 760623,
                    "personal": "abc"
                }
            ],
            "headers": [
                {
                    "name": "From",
                    "value": "abc@example.com"
                },
                {
                    "name": "To",
                    "value": "pqr@example.com"
                },
                {
                    "name": "CC",
                    "value": "abc@example.com"
                },
                {
                    "name": "Subject",
                    "value": "craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646"
                },
                {
                    "name": "Thread-Topic",
                    "value": "craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646"
                },
                {
                    "name": "Thread-Index",
                    "value": "AQHYocD7Ut113z4F00uSjzqlEM2clw=="
                },
                {
                    "name": "Date",
                    "value": "Wed, 27 Jul 2022 13:58:43 +0000"
                },
                {
                    "name": "Message-ID",
                    "value": "<1216208547.160.1658930322668@6d14a4fa9032>"
                }
            ],
            "id": 760623,
            "internetMessageId": "<1216208547.160.1658930322668@6d14a4fa9032>",
            "md5": "a486b023cd82f45f7b099a41dc3776a6",
            "processedOn": "2022-07-27T13:58:46.271+00:00",
            "receivedOn": "2022-07-27T13:58:44.000+00:00",
            "recipients": [
                {
                    "address": "abc@example.com",
                    "id": 7606409,
                    "personal": "abc",
                    "recipientType": "cc"
                },
                {
                    "address": "pqr@example.com",
                    "id": 7606410,
                    "personal": "pqr",
                    "recipientType": "to"
                }
            ],
            "sentOn": "2022-07-27T13:58:43.000+00:00",
            "sha1": "0b744bed73106d5d613d83c71b9d9884f48690f4",
            "sha256": "2d7bad3fe37c9e4089e6231784f51354ef2fd9689fe7fae6d46cb70d279da8e0",
            "subject": "craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646"
        }
    }
}
```

#### Human Readable Output

>### Message Metadata:
>|ID|Subject|Received On|Sent On|Processed On|Sender|Recipients|MD5|SHA1|SHA256|Internet Message ID|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 760623 | craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646 | 27/07/2022, 01:58 PM UTC | 27/07/2022, 01:58 PM UTC | 27/07/2022, 01:58 PM UTC | abc@example.com | abc@example.com<br/>pqr@example.com | a486b023cd82f45f7b099a41dc3776a6 | 0b744bed73106d5d613d83c71b9d9884f48690f4 | 2d7bad3fe37c9e4089e6231784f51354ef2fd9689fe7fae6d46cb70d279da8e0 | <1216208547.160.1658930322668@6d14a4fa9032\> |


### cofense-message-get
***
Fetches full content of an email and returns it as a zip file using a token.


#### Base Command

`cofense-message-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | A one-time token to access the content of an email in a zip file.<br/><br/>Note: Users can get the token by executing the "cofense-message-token-get" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

#### Command example
```!cofense-message-get token="fbbeff70-2c17-4d67-a741-3d8a7e394005"```
#### Context Example
```json
{
    "File": {
        "EntryID": "603@cc18bdc4-7c64-494c-879c-23c3aee60818",
        "Info": "text/plain",
        "MD5": "97ee1d575640245abadbba15c0672eec",
        "Name": "13311",
        "SHA1": "13395876300d0a575812878446e15b9bbddda0b2",
        "SHA256": "19d9c63bf4067a897950cfb72c14e8d05d8dcab0655979c6b60b925fb91e329f",
        "SHA512": "31df48f235cc82247c6edc05850f910d6a057717d5d5f6ce84a4bc6c6fc3cc1f6ebae706ac592ace106b0559753928a838a1aee7018bec5b4316b90d95f55bcf",
        "SSDeep": "24:nDBTBpJG4hbUWBFcXekJPkJ1WkJM8PWkJKckJvV/WskJvV28BesR1zvX0:nDNrHb1BWXekJPkJ1WkJfPWkJDkJvV/n",
        "Size": 988,
        "Type": "ASCII text, with CRLF line terminators"
    }
}
```

#### Human Readable Output

>|EntryID|Info|MD5|Name|SHA1|SHA256|SHA512|SSDeep|Size|Type|
>|---|---|---|---|---|---|---|---|---|---|
>| 603@cc18bdc4-7c64-494c-879c-23c3aee60818 | text/plain | 97ee1d575640245abadbba15c0672eec | 13311 | 13395876300d0a575812878446e15b9bbddda0b2 | 19d9c63bf4067a897950cfb72c14e8d05d8dcab0655979c6b60b925fb91e329f | 31df48f235cc82247c6edc05850f910d6a057717d5d5f6ce84a4bc6c6fc3cc1f6ebae706ac592ace106b0559753928a838a1aee7018bec5b4316b90d95f55bcf | 24:nDBTBpJG4hbUWBFcXekJPkJ1WkJM8PWkJKckJvV/WskJvV28BesR1zvX0:nDNrHb1BWXekJPkJ1WkJfPWkJDkJvV/n | 988 | ASCII text, with CRLF line terminators |


### cofense-message-attachment-get
***
Fetches the full content of an email and returns a zip file.


#### Base Command

`cofense-message-attachment-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | The hex-encoded string that represents an attachment's MD5 hash.<br/><br/>Note: The md5 hash can be retrieved by using the command "cofense-message-search-results-get". | Required | 
| sha256 | The hex-encoded string that represents an attachment's SHA256 hash.<br/><br/>Note: The sha256 hash can be retrieved by using the command "cofense-message-search-results-get". | Optional | 
| file_name | Provide a name to the file with the extension that needs to be downloaded.<br/><br/>Note: The file name can be retrieved by using the command "cofense-message-search-results-get". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file in bytes. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

#### Command example
```!cofense-message-attachment-get md5="3d0e1d68f12afee22ae3e79e01027c7a" file_name="attachment.txt"```
#### Context Example
```json
{
    "File": {
        "EntryID": "603@cc18bdc4-7c64-494c-879c-23c3aee60818",
        "Info": "text/plain",
        "MD5": "97ee1d575640245abadbba15c0672eec",
        "Name": "13311",
        "SHA1": "13395876300d0a575812878446e15b9bbddda0b2",
        "SHA256": "19d9c63bf4067a897950cfb72c14e8d05d8dcab0655979c6b60b925fb91e329f",
        "SHA512": "31df48f235cc82247c6edc05850f910d6a057717d5d5f6ce84a4bc6c6fc3cc1f6ebae706ac592ace106b0559753928a838a1aee7018bec5b4316b90d95f55bcf",
        "SSDeep": "24:nDBTBpJG4hbUWBFcXekJPkJ1WkJM8PWkJKckJvV/WskJvV28BesR1zvX0:nDNrHb1BWXekJPkJ1WkJfPWkJDkJvV/n",
        "Size": 988,
        "Type": "ASCII text, with CRLF line terminators"
    }
}
```

#### Human Readable Output

>|EntryID|Info|MD5|Name|SHA1|SHA256|SHA512|SSDeep|Size|Type|
>|---|---|---|---|---|---|---|---|---|---|
>| 603@cc18bdc4-7c64-494c-879c-23c3aee60818 | text/plain | 97ee1d575640245abadbba15c0672eec | 13311 | 13395876300d0a575812878446e15b9bbddda0b2 | 19d9c63bf4067a897950cfb72c14e8d05d8dcab0655979c6b60b925fb91e329f | 31df48f235cc82247c6edc05850f910d6a057717d5d5f6ce84a4bc6c6fc3cc1f6ebae706ac592ace106b0559753928a838a1aee7018bec5b4316b90d95f55bcf | 24:nDBTBpJG4hbUWBFcXekJPkJ1WkJM8PWkJKckJvV/WskJvV28BesR1zvX0:nDNrHb1BWXekJPkJ1WkJfPWkJDkJvV/n | 988 | ASCII text, with CRLF line terminators |

### cofense-quarantine-jobs-list
***
Filters and returns a paginated list of matching quarantine jobs.


#### Base Command

`cofense-quarantine-jobs-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclude_quarantine_emails | Whether to remove (true) or not remove (false) quarantined emails from the response. Possible values are: True, False. Default is False. | Optional | 
| page | Start page of the results. The value must be a positive integer or 0. Default is 0. | Optional | 
| size | The number of results to retrieve per page. The value must be a positive integer up to 2000. Default is 50. | Optional | 
| sort | The name-value pair defining the order of the response. Comma separated values are supported.<br/><br/>Supported format: propertyName1:sortOrder1,propertyName2:sortOrder2<br/><br/>Supported values for propertyName are: id, createdBy, createdDate, modifiedBy, modifiedDate, stopRequested.<br/><br/>Supported values for sortOrder are: asc, desc. Default is id:asc. | Optional | 
| auto_quarantine | Whether to include auto quarantine jobs (true) or not include auto quarantine jobs (false). Possible values are: True, False. | Optional | 
| include_status | Filters quarantine jobs by including emails with the specified status. Supports comma-separated values.<br/><br/>Supported values are: NEW, PENDING_APPROVAL, QUEUED, RUNNING, COMPLETED, FAILED.<br/><br/>Where,<br/>NEW: Job was created but is not yet queued.<br/>PENDING_APPROVAL: Job was created from an auto quarantine action and is waiting for approval to run.<br/>QUEUED: Job is queued but has not yet run.<br/>RUNNING: Job is currently running.<br/>COMPLETED: Job run finished and emails were quarantined or restored.<br/>FAILED: Job run finished but some emails to be quarantined or restored are in an error state. Cofense Vision retries failed jobs until the retry limit is reached. | Optional | 
| exclude_status | Filters quarantine jobs by excluding emails with the specified status. Supports comma-separated values.<br/><br/>Supported values are: NEW, PENDING_APPROVAL, QUEUED, RUNNING, COMPLETED, FAILED.<br/><br/>Where,<br/>NEW: Job was created but is not yet queued.<br/>PENDING_APPROVAL: Job was created from an auto quarantine action and is waiting for approval to run.<br/>QUEUED: Job is queued but has not yet run.<br/>RUNNING: Job is currently running.<br/>COMPLETED: Job run finished and emails were quarantined or restored.<br/>FAILED: Job run finished but some emails to be quarantined or restored are in an error state. Cofense Vision retries failed jobs until the retry limit is reached. | Optional | 
| iocs | Unique MD5 hash identifier of one or more IOCs. Comma separated values are supported.<br/><br/>Example: <br/>07fa1e91f99050521a87edc784e83fd5,07123459050525189160784e83fd5. | Optional | 
| modified_date_after | Emails modified after this date and time. The date and time must be in UTC.<br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z. | Optional | 
| sources | One or more configured IOC sources. Comma separated values are supported.<br/><br/>Example: Intelligence, Triage-1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.QuarantineJob.id | Number | ID of the quarantine job in cofense vision. | 
| Cofense.QuarantineJob.createdBy | String | Client that created the quarantine job. | 
| Cofense.QuarantineJob.createdDate | Date | Date and time the quarantine job was created. The timestamp is in UTC. | 
| Cofense.QuarantineJob.modifiedBy | String | Client that last updated the quarantine job. | 
| Cofense.QuarantineJob.modifiedDate | Date | Date and time the quarantine job was last modified. The timestamp is in UTC. | 
| Cofense.QuarantineJob.stopRequested | Boolean | Whether a request was issued \(true\) or was not issued \(false\) to stop the quarantine job. | 
| Cofense.QuarantineJob.emailCount | Number | Number of emails quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.createdDate | Date | Date the quarantine job was created. | 
| Cofense.QuarantineJob.quarantineEmails.errorMessage | String | Error message. | 
| Cofense.QuarantineJob.quarantineEmails.ewsMessageId | String | ID of the email in EWS. | 
| Cofense.QuarantineJob.quarantineEmails.id | Number | ID in cofense vision. | 
| Cofense.QuarantineJob.quarantineEmails.internetMessageID | String | ID of the email assigned by the message transfer agent. | 
| Cofense.QuarantineJob.quarantineEmails.originalFolderId | String | ID of the EWS folder where the email was located before it was quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.quarantinedDate | Date | The date when an email was quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.recipientAddress | String | Email address of the account containing the emails to be quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.status | String | Status of the email. | 
| Cofense.QuarantineJob.quarantineJobRuns.completedDate | Date | Date the quarantine job completed. | 
| Cofense.QuarantineJob.quarantineJobRuns.error | Number | Total number of errors in the quarantine job. | 
| Cofense.QuarantineJob.quarantineJobRuns.id | Number | ID of the quarantine job in Cofense Vision. | 
| Cofense.QuarantineJob.quarantineJobRuns.jobRunType | String | Type of Job depending on the operation being performed against the emails. | 
| Cofense.QuarantineJob.quarantineJobRuns.startedDate | Date | Date the quarantine job started. | 
| Cofense.QuarantineJob.quarantineJobRuns.status | String | Status of the quarantine job. | 
| Cofense.QuarantineJob.quarantineJobRuns.total | Number | Total number of emails in the quarantine job. | 
| Cofense.QuarantineJob.autoQuarantine | Boolean | Whether the quarantine job was part of an auto quarantine action \(true\) or was not part of an auto quarantine action \(false\). | 
| Cofense.QuarantineJob.matchingIOCs | Unknown | MD5 hash of one or more matching IOCs. | 
| Cofense.QuarantineJob.matchingSources | Unknown | One or more IOC sources. | 
| Cofense.QuarantineJob.matchingIocInfo.id | String | MD5 hash composed of the UTF-8 concatenation of "threat_type" and "threat_value" attributes. | 
| Cofense.QuarantineJob.matchingIocInfo.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.QuarantineJob.matchingIocInfo.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.QuarantineJob.matchingIocInfo.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.source | Unknown | Data that the IOC source reads and writes. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.expires_at | Date | Date and time in UTC, after which this IOC expires. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.first_quarantined_at | Date | Date and time Cofense Vision quarantined the first email due to this IOC. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.last_quarantined_at | Date | Date and time Cofense Vision quarantined the last email due to this IOC. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.quarantine_count | Number | Number of recipients who received emails matching the IOC while the IOC was active. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| Cofense.QuarantineJob.searchId | Number | ID that Cofense Vision assigned to the search, if any. | 

#### Command example
```!cofense-quarantine-jobs-list size=2```
#### Context Example
```json
{
    "Cofense": {
        "QuarantineJob": [
            {
                "autoQuarantine": false,
                "createdBy": "testuser",
                "createdDate": "2022-07-07T07:36:09.097744",
                "emailCount": 1,
                "id": 8,
                "modifiedBy": "system",
                "modifiedDate": "2022-07-20T05:37:41.585128",
                "quarantineEmails": [
                    {
                        "createdDate": "2022-07-07T07:29:23.535483",
                        "errorMessage": "No primary addresses were found for 3/xxxxx@muczynskicofense.onmicrosoft.com",
                        "id": 3,
                        "internetMessageId": "<1341250439.1013918.1657064008682@af226d4cfbab>",
                        "recipientAddress": "abc@example.com",
                        "status": "NOT_FOUND"
                    }
                ],
                "quarantineJobRuns": [
                    {
                        "completedDate": "2022-07-07T07:36:20.616526",
                        "error": 1,
                        "id": 14,
                        "jobRunType": "QUARANTINE",
                        "startedDate": "2022-07-07T07:36:20.035786",
                        "status": "COMPLETED",
                        "total": 1
                    },
                    {
                        "completedDate": "2022-07-20T05:37:42.31125",
                        "error": 0,
                        "id": 440,
                        "jobRunType": "RESTORE",
                        "startedDate": "2022-07-20T05:37:41.585443",
                        "status": "COMPLETED",
                        "total": 1
                    }
                ],
                "stopRequested": true
            },
            {
                "autoQuarantine": false,
                "createdBy": "testuser",
                "createdDate": "2022-07-07T09:19:07.29997",
                "emailCount": 1,
                "id": 12,
                "modifiedBy": "system",
                "modifiedDate": "2022-08-09T11:23:22.074202",
                "quarantineEmails": [
                    {
                        "createdDate": "2022-07-07T06:46:34.76681",
                        "errorMessage": "No primary addresses were found for 1/xxxxx@muczynskicofense.onmicrosoft.com",
                        "ewsMessageId": "AAMkADgyNjJmMzg0LTI1NjgtNDkzMi04OWM4LTQ0YmMxZGMyNjViOABGAAAAAAA2/UgfwINITKjcFdr2xiIPBwDd+41JQMRFTYDq3CRJ00qJAABhEUxVAADd+41JQMRFTYDq3CRJ00qJAABoQNd2AAA=",
                        "id": 1,
                        "internetMessageId": "<999389937.952188.1657035399834@af226d4cfbab>",
                        "originalFolderId": "AQMkADgyNjJmMzg0LTI1NjgtNDkzMi04OWM4LTQ0AGJjMWRjMjY1YjgALgAAAzb9SB/Ag0hMqNwV2vbGIg8BAN37jUlAxEVNgOrcJEnTSokAAAIBJAAAAA==",
                        "quarantinedDate": "2022-07-15T09:24:59.469491",
                        "recipientAddress": "pqr@example.com",
                        "status": "NOT_FOUND"
                    }
                ],
                "quarantineJobRuns": [
                    {
                        "completedDate": "2022-07-07T09:19:22.014868",
                        "error": 1,
                        "id": 45,
                        "jobRunType": "QUARANTINE",
                        "startedDate": "2022-07-07T09:19:21.583128",
                        "status": "COMPLETED",
                        "total": 1
                    },
                    {
                        "completedDate": "2022-08-09T11:23:22.578602",
                        "error": 0,
                        "id": 839,
                        "jobRunType": "RESTORE",
                        "startedDate": "2022-08-09T11:23:22.076621",
                        "status": "COMPLETED",
                        "total": 1
                    }
                ],
                "stopRequested": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Quarantine Job:
>|ID|Created By|Created Date|Last Modified By|Last Modified Date|Last Action|Status|Completed Date|Messages|
>|---|---|---|---|---|---|---|---|---|
>| 8 | testuser | 07/07/2022, 07:36 AM  | system | 20/07/2022, 05:37 AM  | RESTORE | COMPLETED | 20/07/2022, 05:37 AM  | 1 |
>| 12 | testuser | 07/07/2022, 09:19 AM  | system | 09/08/2022, 11:23 AM  | RESTORE | COMPLETED | 09/08/2022, 11:23 AM  | 1 |


### cofense-quarantine-job-create
***
Creates a new quarantine job.


#### Base Command

`cofense-quarantine-job-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| quarantine_emails | A comma-separated string of quarantine emails, specifying the internet <br/>message ID and the recipient address of the email.<br/><br/>Supported format:<br/>internetMessageID1:recipientAddress1, internetMessageID2:recipientAddress2<br/><br/>Where,<br/>internetMessageID: IDs of any emails in the particular account to be<br/>quarantined, with each internet message ID enclosed in angle brackets.<br/><br/>recipientAddress: Email address of the account containing the emails to be quarantined.<br/><br/>Example: &lt;513C8CD8-E593-4DC4-82BF6202E8AC95CB&gt;:mail054@example.com,<br/>&lt;41348CD8-E593-4DC4-82BF6202E8AC95CB&gt;:ma32il054@example.com<br/><br/>Note: Users can get the internet message ID and recipient address by<br/>executing the "cofense-message-search-results-get" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.QuarantineJob.id | Number | ID of the quarantine job in cofense vision. | 
| Cofense.QuarantineJob.createdBy | String | Client that created the quarantine job. | 
| Cofense.QuarantineJob.createdDate | Date | Date and time the quarantine job was created. The timestamp is in UTC. | 
| Cofense.QuarantineJob.modifiedBy | String | Client that last updated the quarantine job. | 
| Cofense.QuarantineJob.modifiedDate | Date | Date and time the quarantine job was last modified. The timestamp is in UTC. | 
| Cofense.QuarantineJob.stopRequested | Boolean | Whether a request was issued \(true\) or was not issued \(false\) to stop the quarantine job. | 
| Cofense.QuarantineJob.emailCount | Number | Number of emails quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.createdDate | Date | Date the quarantine job was created. | 
| Cofense.QuarantineJob.quarantineEmails.errorMessage | String | Error message. | 
| Cofense.QuarantineJob.quarantineEmails.ewsMessageId | String | ID of the email in EWS. | 
| Cofense.QuarantineJob.quarantineEmails.id | Number | ID in cofense vision. | 
| Cofense.QuarantineJob.quarantineEmails.internetMessageID | String | ID of the email assigned by the message transfer agent. | 
| Cofense.QuarantineJob.quarantineEmails.originalFolderId | String | ID of the EWS folder where the email was located before it was quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.quarantinedDate | Date | Date the email was quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.recipientAddress | String | Email address of the account containing the emails to be quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.status | String | Status of the email. | 
| Cofense.QuarantineJob.quarantineJobRuns.completedDate | Date | Date the quarantine job completed. | 
| Cofense.QuarantineJob.quarantineJobRuns.error | Number | Total number of errors in the quarantine job. | 
| Cofense.QuarantineJob.quarantineJobRuns.id | Number | ID of the quarantine job in Cofense Vision. | 
| Cofense.QuarantineJob.quarantineJobRuns.jobRunType | String | Type of Job depending on the operation being performed against the emails. | 
| Cofense.QuarantineJob.quarantineJobRuns.startedDate | Date | Date the quarantine job started. | 
| Cofense.QuarantineJob.quarantineJobRuns.status | String | Status of the quarantine job. | 
| Cofense.QuarantineJob.quarantineJobRuns.total | Number | Total number of emails in the quarantine job. | 
| Cofense.QuarantineJob.autoQuarantine | Boolean | Whether the quarantine job was part of an auto quarantine action \(true\) or was not part of an auto quarantine action \(false\). | 
| Cofense.QuarantineJob.matchingIOCs | Unknown | MD5 hash of one or more matching IOCs. | 
| Cofense.QuarantineJob.matchingSources | Unknown | One or more IOC sources. | 
| Cofense.QuarantineJob.matchingIocInfo.id | String | MD5 hash composed of the UTF-8 concatenation of "threat_type" and "threat_value" attributes. | 
| Cofense.QuarantineJob.matchingIocInfo.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.QuarantineJob.matchingIocInfo.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.QuarantineJob.matchingIocInfo.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.source | Unknown | Data that the IOC source reads and writes. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.expires_at | Date | Date and time, in UTC, after which this IOC expires. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.first_quarantined_at | Date | Date and time Cofense Vision quarantined the first email due to this IOC. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.last_quarantined_at | Date | Date and time Cofense Vision quarantined the last email due to this IOC. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.quarantine_count | Number | Number of recipients who received emails matching the IOC while the IOC was active. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| Cofense.QuarantineJob.searchId | Number | ID that Cofense Vision assigned to the search, if any. | 

#### Command example
```!cofense-quarantine-job-create quarantine_emails="<test-id>:test@example.com"```
#### Context Example
```json
{
    "Cofense": {
        "QuarantineJob": {
            "autoQuarantine": false,
            "createdBy": "testuser",
            "createdDate": "2022-08-10T04:23:57.442172557",
            "emailCount": 1,
            "id": 431,
            "modifiedBy": "testuser",
            "modifiedDate": "2022-08-10T04:23:57.442172557",
            "quarantineEmails": [
                {
                    "createdDate": "2022-08-08T09:15:46.921796",
                    "errorMessage": "No primary addresses were found for 5578/xxxxx@example.com",
                    "id": 5578,
                    "internetMessageId": "<test-id>",
                    "recipientAddress": "test@example.com",
                    "status": "UNKNOWN_MAILBOX"
                }
            ],
            "quarantineJobRuns": [
                {
                    "error": 0,
                    "id": 860,
                    "jobRunType": "QUARANTINE",
                    "status": "NEW",
                    "total": 1
                }
            ],
            "stopRequested": false
        }
    }
}
```

#### Human Readable Output

>### Quarantine job create:
>#### Quarantine job has been created successfully.
>|ID|Created By|Created Date|Last Modified By|Last Modified Date|Messages|
>|---|---|---|---|---|---|
>| 431 | testuser | 10/08/2022, 04:23 AM  | testuser | 10/08/2022, 04:23 AM  | 1 |


### cofense-quarantine-job-delete
***
Deletes the quarantine job identified by its unique ID.


#### Base Command

`cofense-quarantine-job-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the quarantine job in cofense vision to be deleted.<br/><br/>Note: Users can get the list of IDs by executing the "cofense-quarantine-jobs-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.QuarantineJob.id | Number | ID of the quarantine job in cofense vision. | 
| Cofense.QuarantineJob.isDeleted | Boolean | Whether the quarantine job is successfully deleted\(true\) or not\(false\). | 

#### Command example
```!cofense-quarantine-job-delete id=266```
#### Context Example
```json
{
    "Cofense": {
        "QuarantineJob": {
            "id": "266",
            "isDeleted": true
        }
    }
}
```

#### Human Readable Output

>## Quarantine Job with ID 266 is successfully deleted.

### cofense-quarantine-job-get
***
Retrieves quarantine job identified by its unique ID.


#### Base Command

`cofense-quarantine-job-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the quarantine job in cofense vision to be retrieved.<br/><br/>Note: Users can get the list of IDs by executing the "cofense-quarantine-jobs-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.QuarantineJob.id | Number | ID of the quarantine job in cofense vision. | 
| Cofense.QuarantineJob.createdBy | String | Client that created the quarantine job. | 
| Cofense.QuarantineJob.createdDate | Date | Date and time the quarantine job was created. The timestamp is in UTC. | 
| Cofense.QuarantineJob.modifiedBy | String | Client that last updated the quarantine job. | 
| Cofense.QuarantineJob.modifiedDate | Date | Date and time the quarantine job was last modified. The timestamp is in UTC. | 
| Cofense.QuarantineJob.stopRequested | Boolean | Whether a request was issued \(true\) or was not issued \(false\) to stop the quarantine job. | 
| Cofense.QuarantineJob.emailCount | Number | Number of emails quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.createdDate | Date | Date the quarantine job was created. | 
| Cofense.QuarantineJob.quarantineEmails.errorMessage | String | Error message. | 
| Cofense.QuarantineJob.quarantineEmails.ewsMessageId | String | ID of the email in EWS. | 
| Cofense.QuarantineJob.quarantineEmails.id | Number | ID in cofense vision. | 
| Cofense.QuarantineJob.quarantineEmails.internetMessageID | String | ID of the email assigned by the message transfer agent. | 
| Cofense.QuarantineJob.quarantineEmails.originalFolderId | String | ID of the EWS folder where the email was located before it was quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.quarantinedDate | Date | Date the email was quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.recipientAddress | String | Email address of the account containing the emails to be quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.status | String | Status of the email. | 
| Cofense.QuarantineJob.quarantineJobRuns.completedDate | Date | Date the quarantine job completed. | 
| Cofense.QuarantineJob.quarantineJobRuns.error | Number | Total number of errors in the quarantine job. | 
| Cofense.QuarantineJob.quarantineJobRuns.id | Number | ID of the quarantine job in Cofense Vision. | 
| Cofense.QuarantineJob.quarantineJobRuns.jobRunType | String | Type of Job depending on the operation being performed against the emails. | 
| Cofense.QuarantineJob.quarantineJobRuns.startedDate | Date | Date the quarantine job started. | 
| Cofense.QuarantineJob.quarantineJobRuns.status | String | Status of the quarantine job. | 
| Cofense.QuarantineJob.quarantineJobRuns.total | Number | Total number of emails in the quarantine job. | 
| Cofense.QuarantineJob.autoQuarantine | Boolean | Whether the quarantine job was part of an auto quarantine action \(true\) or was not part of an auto quarantine action \(false\). | 
| Cofense.QuarantineJob.matchingIOCs | Unknown | MD5 hash of one or more matching IOCs. | 
| Cofense.QuarantineJob.matchingSources | Unknown | One or more IOC sources. | 
| Cofense.QuarantineJob.matchingIocInfo.id | String | MD5 hash composed of the UTF-8 concatenation of "threat_type" and "threat_value" attributes. | 
| Cofense.QuarantineJob.matchingIocInfo.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.QuarantineJob.matchingIocInfo.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.QuarantineJob.matchingIocInfo.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.source | Unknown | Data that the IOC source reads and writes. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.expires_at | Date | Date and time in UTC, after which this IOC expires. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.first_quarantined_at | Date | Date and time Cofense Vision quarantined the first email due to this IOC. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.last_quarantined_at | Date | Date and time Cofense Vision quarantined the last email due to this IOC. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.quarantine_count | Number | Number of recipients who received emails matching the IOC while the IOC was active. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| Cofense.QuarantineJob.searchId | Number | ID that Cofense Vision assigned to the search, if any. | 

#### Command example
```!cofense-quarantine-job-get id=100```
#### Context Example
```json
{
    "Cofense": {
        "QuarantineJob": {
            "autoQuarantine": false,
            "createdBy": "testuser",
            "createdDate": "2022-07-08T15:49:19.302416",
            "emailCount": 10,
            "id": 100,
            "modifiedBy": "testuser",
            "modifiedDate": "2022-08-09T11:36:35.996422",
            "quarantineEmails": [
                {
                    "createdDate": "2022-07-08T15:49:16.87704",
                    "ewsMessageId": "AAMkAGJhMGUzOTc2LTYxNjEtNDRlYi1hNWRmLWQyMGE5ZWZkY2JlOQBGAAAAAACYdf11Yr3QRIC86wUeQZguBwAMKVxfPrXHRbB4YDM6zXqKAABm5hr/AAAMKVxfPrXHRbB4YDM6zXqKAABm5h7VAAA=",
                    "id": 67,
                    "internetMessageId": "<1178768708.1512835.1657295339501@af226d4cfbab>",
                    "originalFolderId": "AQMkAGJhMGUzOTc2LTYxNjEtNDQAZWItYTVkZi1kMjBhOWVmZGNiZTkALgAAA5h1/XVivdBEgLzrBR5BmC4BAAwpXF8+tcdFsHhgMzrNeooAAAIBDAAAAA==",
                    "quarantinedDate": "2022-07-08T15:49:38.563419",
                    "recipientAddress": "abc@example.com",
                    "status": "NOT_FOUND"
                },
                {
                    "createdDate": "2022-07-08T15:49:16.89515",
                    "ewsMessageId": "AAMkADBkODY5OTkzLTFhMDMtNDUxZC05MTY4LTU1MWMzYmU2ZGM0YgBGAAAAAADHqxFyD0K3TI6sCxIePsQSBwALsQhDVRPPQpNK3uNfrckFAABmyPjPAAALsQhDVRPPQpNK3uNfrckFAABmyPylAAA=",
                    "id": 76,
                    "internetMessageId": "<1178768708.1512835.1657295339501@af226d4cfbab>",
                    "originalFolderId": "AQMkADBkODY5OQEzLTFhMDMtNDUxZC05MTY4LTU1ADFjM2JlNmRjNGIALgAAA8erEXIPQrdMjqwLEh4+xBIBAAuxCENVE89Ck0re41+tyQUAAAIBDAAAAA==",
                    "quarantinedDate": "2022-07-08T15:49:34.372725",
                    "recipientAddress": "pqr@example.com",
                    "status": "NOT_FOUND"
                }
            ],
            "quarantineJobRuns": [
                {
                    "completedDate": "2022-07-08T15:49:41.865254",
                    "error": 0,
                    "id": 232,
                    "jobRunType": "QUARANTINE",
                    "startedDate": "2022-07-08T15:49:25.956206",
                    "status": "COMPLETED",
                    "total": 10
                },
                {
                    "completedDate": "2022-08-09T11:36:29.566425",
                    "error": 0,
                    "id": 841,
                    "jobRunType": "RESTORE",
                    "startedDate": "2022-08-09T11:36:22.344285",
                    "status": "COMPLETED",
                    "total": 10
                }
            ],
            "searchId": 402,
            "stopRequested": true
        }
    }
}
```

#### Human Readable Output

>### Quarantine Job:
>|ID|Search ID|Created By|Created Date|Last Modified By|Last Modified Date|Last Action|Status|Completed Date|Messages|
>|---|---|---|---|---|---|---|---|---|---|
>| 100 | 402 | testuser | 08/07/2022, 03:49 PM  | testuser | 09/08/2022, 11:36 AM  | RESTORE | COMPLETED | 09/08/2022, 11:36 AM  | 10 |


### cofense-quarantine-job-restore
***
Restores emails quarantined by the job identified by its unique ID.


#### Base Command

`cofense-quarantine-job-restore`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the quarantine job in cofense vision to be restored.<br/><br/>Note: Users can get the list of ID by executing the "cofense-quarantine-jobs-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.QuarantineJob.id | Number | ID of the quarantine job in cofense vision. | 
| Cofense.QuarantineJob.isRestored | Boolean | Whether the quarantine job is successfully restored\(true\) or not\(false\). | 

#### Command example
```!cofense-quarantine-job-restore id=100```
#### Context Example
```json
{
    "Cofense": {
        "QuarantineJob": {
            "id": "100",
            "isRestored": true
        }
    }
}
```

#### Human Readable Output

>## Emails quarantined by the quarantine job ID 100 have been successfully restored.

### cofense-quarantine-job-approve
***
Approves the quarantine job identified by its unique ID. When the "Auto Quarantine" feature is configured which requires manual approvals, this command can approve all the pending quarantine jobs.


#### Base Command

`cofense-quarantine-job-approve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the quarantine job in cofense vision to be approved.<br/><br/>Note: Users can get the list of IDs by executing the "cofense-quarantine-jobs-list" command. | Required | 
| message_count | Number of emails containing IOC matches to be quarantined. When message_count is present, cofense vision quarantines a subset of the total number of emails containing IOC matches. The value must be a non-zero and positive integer. If message_count is not present, all messages will be approved. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.QuarantineJob.id | Number | ID of the quarantine job in cofense vision. | 
| Cofense.QuarantineJob.isApproved | Boolean | Whether the quarantine job is successfully approved\(true\) or not\(false\). | 

#### Command example
```!cofense-quarantine-job-approve id=430 message_count=1```
#### Context Example
```json
{
    "Cofense": {
        "QuarantineJob": {
            "id": "430",
            "isApproved": true
        }
    }
}
```

#### Human Readable Output

>## Quarantine Job with ID 430 has been approved successfully.

### cofense-quarantine-job-stop
***
Issues a request to stop the quarantine job identified by its unique ID.


#### Base Command

`cofense-quarantine-job-stop`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the quarantine job in cofense vision to be stopped.<br/><br/>Note: Users can get the list of IDs by executing the "cofense-quarantine-jobs-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.QuarantineJob.id | Number | ID of the quarantine job in cofense vision. | 
| Cofense.QuarantineJob.createdBy | String | Client that created the quarantine job. | 
| Cofense.QuarantineJob.createdDate | Date | Date and time the quarantine job was created. The timestamp is in UTC. | 
| Cofense.QuarantineJob.modifiedBy | String | Client that last updated the quarantine job. | 
| Cofense.QuarantineJob.modifiedDate | Date | Date and time the quarantine job was last modified. The timestamp is in UTC. | 
| Cofense.QuarantineJob.stopRequested | Boolean | Whether a request was issued \(true\) or was not issued \(false\) to stop the quarantine job. | 
| Cofense.QuarantineJob.emailCount | Number | Number of emails quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.createdDate | Date | Date the quarantine job was created. | 
| Cofense.QuarantineJob.quarantineEmails.errorMessage | String | Error message. | 
| Cofense.QuarantineJob.quarantineEmails.ewsMessageId | String | ID of the email in EWS. | 
| Cofense.QuarantineJob.quarantineEmails.id | Number | ID in cofense vision. | 
| Cofense.QuarantineJob.quarantineEmails.internetMessageID | String | ID of the email assigned by the message transfer agent. | 
| Cofense.QuarantineJob.quarantineEmails.originalFolderId | String | ID of the EWS folder where the email was located before it was quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.quarantinedDate | Date | Date the email was quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.recipientAddress | String | Email address of the account containing the emails to be quarantined. | 
| Cofense.QuarantineJob.quarantineEmails.status | String | Status of the email. | 
| Cofense.QuarantineJob.quarantineJobRuns.completedDate | Date | Date the quarantine job completed. | 
| Cofense.QuarantineJob.quarantineJobRuns.error | Number | Total number of errors in the quarantine job. | 
| Cofense.QuarantineJob.quarantineJobRuns.id | Number | ID of the quarantine job in Cofense Vision. | 
| Cofense.QuarantineJob.quarantineJobRuns.jobRunType | String | Type of Job depending on the operation being performed against the emails. | 
| Cofense.QuarantineJob.quarantineJobRuns.startedDate | Date | Date the quarantine job started. | 
| Cofense.QuarantineJob.quarantineJobRuns.status | String | Status of the quarantine job. | 
| Cofense.QuarantineJob.quarantineJobRuns.total | Number | Total number of emails in the quarantine job. | 
| Cofense.QuarantineJob.autoQuarantine | Boolean | Whether the quarantine job was part of an auto quarantine action \(true\) or was not part of an auto quarantine action \(false\). | 
| Cofense.QuarantineJob.matchingIOCs | Unknown | MD5 hash of one or more matching IOCs. | 
| Cofense.QuarantineJob.matchingSources | Unknown | One or more IOC sources. | 
| Cofense.QuarantineJob.matchingIocInfo.id | String | MD5 hash composed of the UTF-8 concatenation of "threat_type" and "threat_value" attributes. | 
| Cofense.QuarantineJob.matchingIocInfo.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.QuarantineJob.matchingIocInfo.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.QuarantineJob.matchingIocInfo.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.source | Unknown | Data that the IOC source reads and writes. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.expires_at | Date | Date and time in UTC, after which this IOC expires. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.first_quarantined_at | Date | Date and time Cofense Vision quarantined the first email due to this IOC. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.last_quarantined_at | Date | Date and time Cofense Vision quarantined the last email due to this IOC. The timestamp is in UTC. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.quarantine_count | Number | Number of recipients who received emails matching the IOC while the IOC was active. | 
| Cofense.QuarantineJob.matchingIocInfo.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| Cofense.QuarantineJob.searchId | Number | ID that Cofense Vision assigned to the search, if any. | 

#### Command example
```!cofense-quarantine-job-stop id=100```
#### Context Example
```json
{
    "Cofense": {
        "QuarantineJob": {
            "autoQuarantine": false,
            "createdBy": "testuser",
            "createdDate": "2022-07-08T15:49:19.302416",
            "emailCount": 10,
            "id": 100,
            "modifiedBy": "testuser",
            "modifiedDate": "2022-08-10T04:24:37.004847",
            "quarantineEmails": [
                {
                    "createdDate": "2022-07-08T15:49:16.87704",
                    "ewsMessageId": "AAMkAGJhMGUzOTc2LTYxNjEtNDRlYi1hNWRmLWQyMGE5ZWZkY2JlOQBGAAAAAACYdf11Yr3QRIC86wUeQZguBwAMKVxfPrXHRbB4YDM6zXqKAABm5hr/AAAMKVxfPrXHRbB4YDM6zXqKAABm5h7VAAA=",
                    "id": 67,
                    "internetMessageId": "<1178768708.1512835.1657295339501@af226d4cfbab>",
                    "originalFolderId": "AQMkAGJhMGUzOTc2LTYxNjEtNDQAZWItYTVkZi1kMjBhOWVmZGNiZTkALgAAA5h1/XVivdBEgLzrBR5BmC4BAAwpXF8+tcdFsHhgMzrNeooAAAIBDAAAAA==",
                    "quarantinedDate": "2022-07-08T15:49:38.563419",
                    "recipientAddress": "abc@example.com",
                    "status": "NOT_FOUND"
                },
                {
                    "createdDate": "2022-07-08T15:49:16.89515",
                    "ewsMessageId": "AAMkADBkODY5OTkzLTFhMDMtNDUxZC05MTY4LTU1MWMzYmU2ZGM0YgBGAAAAAADHqxFyD0K3TI6sCxIePsQSBwALsQhDVRPPQpNK3uNfrckFAABmyPjPAAALsQhDVRPPQpNK3uNfrckFAABmyPylAAA=",
                    "id": 76,
                    "internetMessageId": "<1178768708.1512835.1657295339501@af226d4cfbab>",
                    "originalFolderId": "AQMkADBkODY5OQEzLTFhMDMtNDUxZC05MTY4LTU1ADFjM2JlNmRjNGIALgAAA8erEXIPQrdMjqwLEh4+xBIBAAuxCENVE89Ck0re41+tyQUAAAIBDAAAAA==",
                    "quarantinedDate": "2022-07-08T15:49:34.372725",
                    "recipientAddress": "pqr@example.com",
                    "status": "NOT_FOUND"
                }
            ],
            "quarantineJobRuns": [
                {
                    "completedDate": "2022-07-08T15:49:41.865254",
                    "error": 0,
                    "id": 232,
                    "jobRunType": "QUARANTINE",
                    "startedDate": "2022-07-08T15:49:25.956206",
                    "status": "COMPLETED",
                    "total": 10
                },
                {
                    "completedDate": "2022-07-08T15:49:58.163195",
                    "error": 0,
                    "id": 233,
                    "jobRunType": "RESTORE",
                    "startedDate": "2022-07-08T15:49:56.006024",
                    "status": "COMPLETED",
                    "total": 10
                },
                {
                    "error": 0,
                    "id": 861,
                    "jobRunType": "RESTORE",
                    "startedDate": "2022-08-10T04:24:24.432429",
                    "status": "RUNNING",
                    "total": 10
                }
            ],
            "searchId": 402,
            "stopRequested": true
        }
    }
}
```

#### Human Readable Output

>### Quarantine job with ID 100 has been successfully stopped.
>|ID|Created By|Created Date|Last Modified By|Last Modified Date|Last Action|Status|Messages|Stopped Quarantine|
>|---|---|---|---|---|---|---|---|---|
>| 100 | testuser | 08/07/2022, 03:49 PM  | testuser | 10/08/2022, 04:24 AM  | RESTORE | RUNNING | 10 | true |


### cofense-message-searches-list
***
Retrieves the list of searches.


#### Base Command

`cofense-message-searches-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The start page of the results. The value must be a positive integer or 0. Default is 0. | Optional | 
| size | The number of results to retrieve per page. The value must be a positive integer up to 2000. Default is 50. | Optional | 
| sort | The name-value pair defining the order of the response. Comma separated values are supported.<br/><br/>Supported format: propertyName1:sortOrder1,propertyName2:sortOrder2<br/><br/>Supported values for propertyName are: id, createdBy, createdDate, modifiedBy, <br/>modifiedDate, receivedAfterDate, receivedBeforeDate.<br/><br/>Supported values for sortOrder are: asc, desc. Default is id:asc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Search.id | String | ID that Cofense Vision assigned to the search. | 
| Cofense.Search.createdBy | String | Username of the client that created the search. | 
| Cofense.Search.createdDate | Date | Date and time the search was created. The timestamp is in UTC. | 
| Cofense.Search.modifiedBy | String | Username of the last client that updated the search. | 
| Cofense.Search.modifiedDate | Date | Date and time the search was last modified. The timestamp is in UTC. | 
| Cofense.Search.subjects | Unknown | List of email subjects. | 
| Cofense.Search.senders | Unknown | List of sender's email addresses. | 
| Cofense.Search.recipient | String | Email address of the recipient. | 
| Cofense.Search.attachmentNames | Unknown | List of attachment file names. | 
| Cofense.Search.attachmentHashCriteria.type | String | The type of matching for attachment hash. | 
| Cofense.Search.attachmentHashCriteria.attachmentHashes.hashType | String | The type of hash. Either MD5 or SHA256. | 
| Cofense.Search.attachmentHashCriteria.attachmentHashes.hashString | String | The hash of the attachment file. | 
| Cofense.Search.domainCriteria.type | String | The type of matching for domains. | 
| Cofense.Search.domainCriteria.domains | Unknown | List of domains. | 
| Cofense.Search.domainCriteria.domains.whiteListUrls | Unknown | List of URLs to white list. | 
| Cofense.Search.attachmentMimeTypes | Unknown | List of MIME types. | 
| Cofense.Search.attachmentExcludeMimeTypes | Unknown | List of MIME types to exclude. | 
| Cofense.Search.receivedAfterDate | Date | Filters for emails received on or after this date and time. | 
| Cofense.Search.receivedBeforeDate | Date | Filters for emails received before or on this date and time. | 
| Cofense.Search.url | String | The URL to search for. | 
| Cofense.Search.internetMessageId | String | Unique identifier of the email. | 
| Cofense.Search.headers.key | String | The name of the key in the header. | 
| Cofense.Search.headers.values | String | The value of the key in the header. | 
| Cofense.Search.partialIngest | Boolean | Indicates whether to search partially ingested emails or not. | 

#### Command example
```!cofense-message-searches-list size=2```
#### Context Example
```json
{
    "Cofense": {
        "Search": [
            {
                "attachmentHashCriteria": {
                    "type": "ANY"
                },
                "createdBy": "testuser",
                "createdDate": "2022-07-11T07:41:25.184255",
                "domainCriteria": {
                    "type": "ANY"
                },
                "id": 430,
                "modifiedBy": "testuser",
                "modifiedDate": "2022-07-11T07:41:25.184255",
                "recipient": "abc@example.com"
            },
            {
                "attachmentHashCriteria": {
                    "type": "ANY"
                },
                "createdBy": "testuser",
                "createdDate": "2022-07-11T07:42:58.176356",
                "domainCriteria": {
                    "type": "ANY"
                },
                "id": 431,
                "modifiedBy": "testuser",
                "modifiedDate": "2022-07-11T07:42:58.176356",
                "recipient": "pqr@example.com",
                "subjects": [
                    "chalk1 time 1657035399833"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Message Searches:
>|ID|Created By|Created Date|Modified By|Modified Date|Recipient|Subjects|
>|---|---|---|---|---|---|---|
>| 430 | testuser | 11/07/2022, 07:41 AM  | testuser | 11/07/2022, 07:41 AM  | abc@example.com |  |
>| 431 | testuser | 11/07/2022, 07:42 AM  | testuser | 11/07/2022, 07:42 AM  | pqr@example.com | chalk1 time 1657035399833 |


### cofense-message-search-get
***
Retrieves the result of the search identified by an ID.


#### Base Command

`cofense-message-search-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The unique ID that cofense vision has assigned to a search.<br/><br/>Note: The ID can be retrieved by using the command "cofense-message-searches-list". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Search.id | String | ID that Cofense Vision assigned to the search. | 
| Cofense.Search.createdBy | String | Username of the client that created the search. | 
| Cofense.Search.createdDate | Date | Date and time the search was created. The timestamp is in UTC. | 
| Cofense.Search.modifiedBy | String | Username of the last client that updated the search. | 
| Cofense.Search.modifiedDate | Date | Date and time the search was last modified. The timestamp is in UTC. | 
| Cofense.Search.subjects | Unknown | List of email subjects. | 
| Cofense.Search.senders | Unknown | List of sender's email addresses. | 
| Cofense.Search.recipient | String | Email address of the recipient. | 
| Cofense.Search.attachmentNames | Unknown | List of attachment file names. | 
| Cofense.Search.attachmentHashCriteria.type | String | The type of matching for attachment hash. | 
| Cofense.Search.attachmentHashCriteria.attachmentHashes.hashType | String | The type of hash. Either MD5 or SHA256. | 
| Cofense.Search.attachmentHashCriteria.attachmentHashes.hashString | String | The hash of the attachment file. | 
| Cofense.Search.domainCriteria.type | String | The type of matching for domains. | 
| Cofense.Search.domainCriteria.domains | Unknown | List of domains. | 
| Cofense.Search.domainCriteria.domains.whiteListUrls | Unknown | List of URLs to white list. | 
| Cofense.Search.attachmentMimeTypes | Unknown | List of MIME types. | 
| Cofense.Search.attachmentExcludeMimeTypes | Unknown | List of MIME types to exclude. | 
| Cofense.Search.receivedAfterDate | Date | Filters the emails received on or after this date and time. | 
| Cofense.Search.receivedBeforeDate | Date | Filters the emails received before or on this date and time. | 
| Cofense.Search.url | String | The URL to be searched for. | 
| Cofense.Search.internetMessageId | String | Unique identifier of the email. | 
| Cofense.Search.headers.key | String | The name of the key in the header. | 
| Cofense.Search.headers.values | String | The value of the key in the header. | 
| Cofense.Search.partialIngest | Boolean | Indicates whether to search partially ingested emails or not. | 

#### Command example
```!cofense-message-search-get id=700```
#### Context Example
```json
{
    "Cofense": {
        "Search": {
            "attachmentHashCriteria": {
                "type": "ANY"
            },
            "createdBy": "testuser",
            "createdDate": "2022-08-02T19:05:08.035549",
            "domainCriteria": {
                "type": "ANY"
            },
            "id": 700,
            "modifiedBy": "testuser",
            "modifiedDate": "2022-08-02T19:05:08.035549"
        }
    }
}
```

#### Human Readable Output

>### Message Search:
>|ID|Created By|Created Date|Modified By|Modified Date|
>|---|---|---|---|---|
>| 700 | testuser | 02/08/2022, 07:05 PM  | testuser | 02/08/2022, 07:05 PM  |


### cofense-message-search-create
***
Creates a new search.


#### Base Command

`cofense-message-search-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subjects | A comma-separated string of subjects to create a search for an email's<br/>subject. It supports the use of one or more wildcard characters (*)<br/>in any position of a subject.<br/><br/>Note: The search can only have a maximum of 3 values. | Optional | 
| senders | A comma-separated string of senders to create a search for an email's<br/>sender. It supports the use of one or more wildcard characters (*)<br/>in any position of a sender's email address.<br/><br/>Note: The search can only have a maximum of 3 values. | Optional | 
| attachment_names | A comma-separated string of attachment names to create a search for an<br/>email's attachments. It supports the use of one or more wildcard<br/>characters (*) in any position of an attachment name.<br/><br/>Note: The search can only have a maximum of 3 values. | Optional | 
| attachment_hash_match_criteria | The type of matching performed on the hashes specified in the attachment_hashes argument.<br/><br/>Possible values are:<br/>ALL: Emails must include all listed attachment hashes.<br/>ANY: Emails must contain at least one of the listed attachment hash. Possible values are: ANY, ALL. Default is ANY. | Optional | 
| attachment_hashes | A comma-separated string of attachment hashes to create a search for an email's attachment hashes.<br/><br/>Supported format: hashtype1:hashvalue1, hashtype2:hashvalue2<br/><br/>Possible values for hashtype are: MD5, SHA256<br/><br/>Example: md5:938c2cc0dcc05f2b68c4287040cfcf71<br/><br/>Note: The search can only have a maximum of 3 values. | Optional | 
| attachment_mime_types | A comma-separated string of MIME types to create a search for an email's attachment MIME type.<br/><br/>Note: The search can only have a maximum of 3 values. | Optional | 
| attachment_exclude_mime_types | A comma-separated string of MIME types to create a search for excluding an email's attachment MIME type.<br/><br/>Note: The search can only have a maximum of 3 values. | Optional | 
| domain_match_criteria | The type of matching to perform on the domains specified in the domains argument.<br/><br/>Possible values are:<br/>ALL: Emails must include all listed domains.<br/>ANY: Emails must contain at least one of the listed domains. Possible values are: ANY, ALL. Default is ANY. | Optional | 
| domains | A comma-separated string of domains to create a search for domains in<br/>an email's body or its attachment. You can change the type of matching<br/>that happens on the specified domains using the domain_match_criteria argument.<br/><br/>Note: The search can only have a maximum of 3 values. | Optional | 
| whitelist_urls | A comma-separated string of URLs to be whitelisted.<br/><br/>Note: The search can only have a maximum of 3 values. | Optional | 
| headers | A comma-separated string of key-value pairs, defining the additional <br/>criteria to search for in the email header.<br/><br/>Supported format: key1:value1, key2:value1:value2:value3<br/><br/>Example: Content-Type:application/json<br/><br/>List of available headers to create a search can be retrieved by<br/>using the command "cofense-searchable-headers-list".<br/><br/>Note: The search can only have a maximum of 3 values. | Optional | 
| internet_message_id | The unique identifier of the email, enclosed in angle brackets. This argument is case-sensitive.<br/><br/>Example:  &lt;513C8CD8-E593-4DC4-82BF6202E8AC95CB@example.com&gt;. | Optional | 
| partial_ingest | Whether to create a search with partially ingested emails (true) or not with partially ingested emails (false). Possible values are: True, False. Default is False. | Optional | 
| received_after_date | Date and time to create a search for emails to specify the received<br/>on or after the specified UTC date and time.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>Example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z. | Optional | 
| received_before_date | Date and time to create a search for emails to specify the received<br/>before or on the specified UTC date and time.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>Example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z. | Optional | 
| recipient | Create a search with the specified recipient. Supports one or more <br/>wildcard characters (*) in any position of a recipient's email address. | Optional | 
| url | Create a search with the specified url. Supports one or more <br/>wildcard characters (*) in any position of the URL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Search.id | String | ID that cofense vision assigned to the search. | 
| Cofense.Search.createdBy | String | Username of the client that created the search. | 
| Cofense.Search.createdDate | Date | Date and time the search was created. The timestamp is in UTC. | 
| Cofense.Search.modifiedBy | String | Username of the last client that updated the search. | 
| Cofense.Search.modifiedDate | Date | Date and time the search was last modified. The timestamp is in UTC. | 
| Cofense.Search.subjects | Unknown | List of email subjects. | 
| Cofense.Search.senders | Unknown | List of sender's email addresses. | 
| Cofense.Search.recipient | String | Email address of the recipient. | 
| Cofense.Search.attachmentNames | Unknown | List of attachment file names. | 
| Cofense.Search.attachmentHashCriteria.type | String | The type of matching for attachment hash. | 
| Cofense.Search.attachmentHashCriteria.attachmentHashes.hashType | String | The type of hash. Either MD5 or SHA256. | 
| Cofense.Search.attachmentHashCriteria.attachmentHashes.hashString | String | The hash of the attachment file. | 
| Cofense.Search.domainCriteria.type | String | The type of matching for domains. | 
| Cofense.Search.domainCriteria.domains | Unknown | List of domains. | 
| Cofense.Search.domainCriteria.domains.whiteListUrls | Unknown | List of URLs to white list. | 
| Cofense.Search.attachmentMimeTypes | Unknown | List of MIME types. | 
| Cofense.Search.attachmentExcludeMimeTypes | Unknown | List of MIME types to exclude. | 
| Cofense.Search.receivedAfterDate | Date | Filters for emails received on or after this date and time. | 
| Cofense.Search.receivedBeforeDate | Date | Filters for emails received before or on this date and time. | 
| Cofense.Search.url | String | The URL to search for. | 
| Cofense.Search.internetMessageId | String | Unique identifier of the email. | 
| Cofense.Search.headers.key | String | The name of the key in the header. | 
| Cofense.Search.headers.values | String | The value of the key in the header. | 
| Cofense.Search.partialIngest | Boolean | Indicates whether to search partially ingested emails or not. | 

#### Command example
```!cofense-message-search-create subjects="test" senders="abc@example.com, pqr@example.com"```
#### Context Example
```json
{
    "Cofense": {
        "Search": {
            "attachmentHashCriteria": {
                "type": "ANY"
            },
            "createdBy": "testuser",
            "createdDate": "2022-08-10T04:25:00.626652162",
            "domainCriteria": {
                "type": "ANY"
            },
            "id": 1091,
            "modifiedBy": "testuser",
            "modifiedDate": "2022-08-10T04:25:00.626652162",
            "partialIngest": false,
            "senders": [
                "abc@example.com",
                "pqr@example.com"
            ],
            "subjects": [
                "test"
            ]
        }
    }
}
```

#### Human Readable Output

>### Message search with ID 1091 has been created successfully.
>|ID|Created By|Created Date|Modified By|Modified Date|Senders|Subjects|Partial Ingest|
>|---|---|---|---|---|---|---|---|
>| 1091 | testuser | 10/08/2022, 04:25 AM  | testuser | 10/08/2022, 04:25 AM  | abc@example.com,<br/>pqr@example.com | test | false |


### cofense-message-search-results-get
***
Retrieves the results for the search identified by the search ID.


#### Base Command

`cofense-message-search-results-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The unique ID that cofense vision has assigned to a search.<br/><br/>Note: The ID can be retrieved by using the command "cofense-message-searches-list". | Required | 
| page | The start page of the results. The value must be a positive integer or 0. Default is 0. | Optional | 
| size | The number of results to retrieve per page. The value must be a positive integer up to 2000. Default is 50. | Optional | 
| sort | The name-value pair defining the order of the response. Comma-separated values are supported.<br/><br/>Supported format: propertyName1:sortOrder1,propertyName2:sortOrder2<br/><br/>Supported values for propertyName are: id, subject, createdOn, sentOn,<br/>htmlBody, md5, sha1, sha256.<br/><br/>Supported values for sortOrder are: asc, desc. Default is id:asc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Search.Message.id | Number | The ID of the message. | 
| Cofense.Search.Message.storageUri | String | Storage URI of the search. | 
| Cofense.Search.Message.subject | String | The subject of the message. | 
| Cofense.Search.Message.receivedOn | Date | The date and time when the message was received by the recipient. | 
| Cofense.Search.Message.sentOn | Date | The date and time when the message was sent by the sender. | 
| Cofense.Search.Message.deliveredOn | Date | The date and time when the message was delivered. | 
| Cofense.Search.Message.processedOn | Date | The date and time Cofense Vision ingested the email. | 
| Cofense.Search.Message.textBody | String | Body of the email in text format. | 
| Cofense.Search.Message.htmlBody | String | Body of the email in HTML format. | 
| Cofense.Search.Message.md5 | String | The MD5 hash of the message. | 
| Cofense.Search.Message.sha1 | String | The SHA1 hash of the message. | 
| Cofense.Search.Message.sha256 | String | The SHA256 hash of the message. | 
| Cofense.Search.Message.internetMessageId | String | Unique identifier of the email. | 
| Cofense.Search.Message.from.id | Number | The ID of the sender. | 
| Cofense.Search.Message.from.personal | String | The name of the sender. | 
| Cofense.Search.Message.from.address | String | The email address of the sender. | 
| Cofense.Search.Message.headers.id | Number | The ID of the header. | 
| Cofense.Search.Message.headers.name | String | The name of the header key. | 
| Cofense.Search.Message.headers.value | String | The value of the header key. | 
| Cofense.Search.Message.headers.seq | Number | Sequence of header field. | 
| Cofense.Search.Message.headers.partialIngest | String | "Null" if no partially ingested messages found; otherwise, one or more of the following to describe the source of the ingestion failure: PARSE, ATTACHMENT, URL, UNKNOWN. | 
| Cofense.Search.Message.recipients.id | Number | The ID of the recipient. | 
| Cofense.Search.Message.recipients.personal | String | The name of the recipient. | 
| Cofense.Search.Message.recipients.address | String | The email address of the recipient. | 
| Cofense.Search.Message.recipients.recipientType | String | The type of the recipient. Whether the recipient is in 'to', 'cc' or in 'bcc'. | 
| Cofense.Search.Message.attachments.size | Number | The size of the attachment file. | 
| Cofense.Search.Message.attachments.filename | String | The name of the attachment file. | 
| Cofense.Search.Message.attachments.contentType | String | The content type present in the header. | 
| Cofense.Search.Message.attachments.detectedContentType | String | The detected content type of the attachment. | 
| Cofense.Search.Message.attachments.md5 | String | The MD5 hash of the attachment. | 
| Cofense.Search.Message.attachments.sha256 | String | The SHA256 hash of the attachment. | 
| Cofense.Search.Message.attachments.id | Number | The ID of the attachment. | 
| Cofense.Search.id | String | ID that cofense vision assigned to the search. | 
| Cofense.Search.createdBy | String | Username of the client that created the search. | 
| Cofense.Search.createdDate | Date | Date and time the search was created. The timestamp is in UTC. | 
| Cofense.Search.modifiedBy | String | Username of the last client that updated the search. | 
| Cofense.Search.modifiedDate | Date | Date and time the search was last modified. The timestamp is in UTC. | 
| Cofense.Search.subjects | Unknown | List of email subjects. | 
| Cofense.Search.senders | Unknown | List of sender's email addresses. | 
| Cofense.Search.recipient | String | Email address of the recipient. | 
| Cofense.Search.attachmentNames | Unknown | List of attachment file names. | 
| Cofense.Search.attachmentHashCriteria.type | String | The type of matching for attachment hash. | 
| Cofense.Search.attachmentHashCriteria.attachmentHashes.hashType | String | The type of hash. Either MD5 or SHA256. | 
| Cofense.Search.attachmentHashCriteria.attachmentHashes.hashString | String | The hash of the attachment file. | 
| Cofense.Search.domainCriteria.type | String | The type of matching for domains. | 
| Cofense.Search.domainCriteria.domains | Unknown | List of domains. | 
| Cofense.Search.domainCriteria.domains.whiteListUrls | Unknown | List of URLs to white list. | 
| Cofense.Search.attachmentMimeTypes | Unknown | List of MIME types. | 
| Cofense.Search.attachmentExcludeMimeTypes | Unknown | List of MIME types to exclude. | 
| Cofense.Search.receivedAfterDate | Date | Filters for emails received on or after this date and time. | 
| Cofense.Search.receivedBeforeDate | Date | Filters for emails received before or on this date and time. | 
| Cofense.Search.url | String | The url to search for. | 
| Cofense.Search.internetMessageId | String | Unique identifier of the email. | 
| Cofense.Search.headers.key | String | The name of the key in the header. | 
| Cofense.Search.headers.values | String | The value of the key in the header. | 
| Cofense.Search.partialIngest | Boolean | Indicates whether to search partially ingested emails or not. | 

#### Command example
```!cofense-message-search-results-get id=700 size=2```
#### Context Example
```json
{
    "Cofense": {
        "Search": {
            "Message": [
                {
                    "attachments": [
                        {
                            "contentType": "text/plain",
                            "detectedContentType": "text/plain",
                            "filename": "fileNum-Thread[mailer-011,5,main]-text-file-163.txt",
                            "id": 1673289,
                            "md5": "3d0e1d68f12afee22ae3e79e01027c7a",
                            "sha256": "ca68f5eecd5822783911ed392fbff3c171d3a1854c0f992364d038ee447f8ac3",
                            "size": 59173
                        },
                        {
                            "contentType": "application/zip",
                            "detectedContentType": "application/zip",
                            "filename": "fileNum-Thread[mailer-011,5,main]-text-file-146.txt.zip",
                            "id": 1673290,
                            "md5": "5c602ca45faac3bb128a5ecbf977f9f1",
                            "sha256": "6018b7cc402e6368d4542c0f6c129a99e35c80ae9001ec338e7621df2f8ac51f",
                            "size": 14563
                        },
                        {
                            "detectedContentType": "text/plain",
                            "filename": "text-file-146.txt",
                            "id": 1673291,
                            "md5": "c5aa88f949574a0a5e75a795dc507da7",
                            "sha256": "d3a070977ae0ae561bae2215526c187d5c46c54dd8899eefb8fe21ed0e6c1303",
                            "size": 27842
                        }
                    ],
                    "from": [
                        {
                            "address": "abc@example.com",
                            "id": 760623,
                            "personal": "mailbox-08517"
                        }
                    ],
                    "headers": [
                        {
                            "name": "From",
                            "value": "abc@example.com"
                        },
                        {
                            "name": "To",
                            "value": "pqr@example.com"
                        },
                        {
                            "name": "CC",
                            "value": "abc@example.com"
                        },
                        {
                            "name": "Subject",
                            "value": "craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646"
                        },
                        {
                            "name": "Thread-Topic",
                            "value": "craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646"
                        },
                        {
                            "name": "Thread-Index",
                            "value": "AQHYocD7Ut113z4F00uSjzqlEM2clw=="
                        },
                        {
                            "name": "Date",
                            "value": "Wed, 27 Jul 2022 13:58:43 +0000"
                        },
                        {
                            "name": "Message-ID",
                            "value": "<1216208547.160.1658930322668@6d14a4fa9032>"
                        }
                    ],
                    "id": 760623,
                    "internetMessageId": "<1216208547.160.1658930322668@6d14a4fa9032>",
                    "md5": "a486b023cd82f45f7b099a41dc3776a6",
                    "processedOn": "2022-07-27T13:58:46.271+00:00",
                    "receivedOn": "2022-07-27T13:58:44.000+00:00",
                    "recipients": [
                        {
                            "address": "abc@example.com",
                            "id": 7606409,
                            "personal": "mailbox-00110",
                            "recipientType": "to"
                        },
                        {
                            "address": "pqr@example.com",
                            "id": 7606418,
                            "personal": "mailbox-00119",
                            "recipientType": "cc"
                        }
                    ],
                    "sentOn": "2022-07-27T13:58:43.000+00:00",
                    "sha1": "0b744bed73106d5d613d83c71b9d9884f48690f4",
                    "sha256": "2d7bad3fe37c9e4089e6231784f51354ef2fd9689fe7fae6d46cb70d279da8e0",
                    "subject": "craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646"
                },
               {
                    "attachments": [
                        {
                            "detectedContentType": "text/plain",
                            "filename": "text-file-146.txt",
                            "id": 1673291,
                            "md5": "c5aa88f949574a0a5e75a795dc507da7",
                            "sha256": "d3a070977ae0ae561bae2215526c187d5c46c54dd8899eefb8fe21ed0e6c1303",
                            "size": 27842
                        }
                    ],
                    "from": [
                        {
                            "address": "abc@example.com",
                            "id": 760623,
                            "personal": "mailbox-08517"
                        }
                    ],
                    "headers": [
                        {
                            "name": "From",
                            "value": "abc@example.com"
                        },
                        {
                            "name": "To",
                            "value": "pqr@example.com"
                        },
                        {
                            "name": "CC",
                            "value": "abc@example.com"
                        },
                        {
                            "name": "Subject",
                            "value": "craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646"
                        },
                        {
                            "name": "Thread-Topic",
                            "value": "craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646"
                        },
                        {
                            "name": "Thread-Index",
                            "value": "AQHYocD7Ut113z4F00uSjzqlEM2clw=="
                        },
                        {
                            "name": "Date",
                            "value": "Wed, 27 Jul 2022 13:58:43 +0000"
                        },
                        {
                            "name": "Message-ID",
                            "value": "<1216208547.160.1658930322668@6d14a4fa9033>"
                        }
                    ],
                    "id": 760624,
                    "internetMessageId": "<1216208547.160.1658930322668@6d14a4fa9033>",
                    "md5": "a486b023cd82f45f7b099a41dc3776a6",
                    "processedOn": "2022-07-27T13:58:46.271+00:00",
                    "receivedOn": "2022-07-27T13:58:44.000+00:00",
                    "recipients": [
                        {
                            "address": "abc@example.com",
                            "id": 7606409,
                            "personal": "mailbox-00110",
                            "recipientType": "to"
                        },
                        {
                            "address": "pqr@example.com",
                            "id": 7606418,
                            "personal": "mailbox-00119",
                            "recipientType": "cc"
                        }
                    ],
                    "sentOn": "2022-07-27T13:58:43.000+00:00",
                    "sha1": "0b744bed73106d5d613d83c71b9d9884f48690f4",
                    "sha256": "2d7bad3fe37c9e4089e6231784f51354ef2fd9689fe7fae6d46cb70d279da8e0",
                    "subject": "craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646"
                }
            ],
            "attachmentHashCriteria": {
                "type": "ANY"
            },
            "createdBy": "testuser",
            "createdDate": "2022-08-02T19:05:08.035549",
            "domainCriteria": {
                "type": "ANY"
            },
            "id": 700,
            "modifiedBy": "testuser",
            "modifiedDate": "2022-08-02T19:05:08.035549"
        }
    }
}
```

#### Human Readable Output

>### Message Search:
>|ID|Created By|Created Date|Modified By|Modified Date|
>|---|---|---|---|---|
>| 700 | testuser | 02/08/2022, 07:05 PM | testuser | 02/08/2022, 07:05 PM |

### Message Search Results:
>|Message ID|Internet Message ID|Subject|Sent On|Received On|Sender|Recipient|Attachment File Names|
>|---|---|---|---|---|---|---|---|
>| 760623 | <1216208547.160.1658930322668@6d14a4fa9032\> | craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646 | 27/07/2022, 01:58 PM UTC | 27/07/2022, 01:58 PM UTC | abc@example.com | abc@example.com,<br/>abc@example.com | File Name: fileNum-Thread[mailer-011,5,main]-text-file-163.txt<br>MD5: 3d0e1d68f12afee22ae3e79e01027c7a<br>SHA256: ca68f5eecd5822783911ed392fbff3c171d3a1854c0f992364d038ee447f8ac3<br><br><br>File Name: fileNum-Thread[mailer-011,5,main]-text-file-146.txt.zip<br>MD5: 5c602ca45faac3bb128a5ecbf977f9f1<br>SHA256: 6018b7cc402e6368d4542c0f6c129a99e35c80ae9001ec338e7621df2f8ac51f<br><br><br>File Name: text-file-146.txt<br>MD5: c5aa88f949574a0a5e75a795dc507da7<br>SHA256: d3a070977ae0ae561bae2215526c187d5c46c54dd8899eefb8fe21ed0e6c1303 |
>| 760624 | <1216208547.160.1658930322668@6d14a4fa9033\> | craftless plantable desulphurate iodized imbeds invoicing infrangibly prosers damn halberdiers refinedly unmoaned scatteredly11 time 1658930322646 | 27/07/2022, 01:58 PM UTC | 27/07/2022, 01:58 PM UTC | abc@example.com | abc@example.com,<br/>abc@example.com | File Name: text-file-146.txt<br>MD5: c5aa88f949574a0a5e75a795dc507da7<br>SHA256: d3a070977ae0ae561bae2215526c187d5c46c54dd8899eefb8fe21ed0e6c1303 |


### cofense-iocs-list
***
Lists the IOCs stored in the local IOC Repository.


#### Base Command

`cofense-iocs-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | A single IOC source value, to fetch the IOCs added or modified by that particular source. The value for source can contain uppercase letters, lowercase letters, numbers, and certain special characters ('.', '_' and '~').<br/><br/>Examples: Triage-1,IOC_Source-2. | Required | 
| page | The start page of the results. The value must be a positive integer or 0. Default is 0. | Optional | 
| size | The number of results to retrieve.<br/><br/>Maximum value is '2000'. Default is 50. | Optional | 
| sort | The name-value pair defining the order of the response.<br/><br/>Supported format: propertyName:sortOrder<br/><br/>Supported value for propertyName is: updatedAt.<br/><br/>Supported values for sortOrder are: asc, desc. | Optional | 
| include_expired | Whether to include expired IOCs or not. Possible values are: True, False. Default is False. | Optional | 
| since | Include only IOCs that were added to the repository after the given UTC date and time.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>Example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.IOC.id | String | MD5 hash composed of the UTF-8 concatenation of "threat_type" and "threat_value" attributes. | 
| Cofense.IOC.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.IOC.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.IOC.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.IOC.metadata.source.threat_level | String | String that describes the severity of the threat. | 
| Cofense.IOC.metadata.source.id | String | Unique identifier assigned by the IOC source. | 
| Cofense.IOC.metadata.source.created_at | Date | Date and time the IOC source included the IOC for the first time. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.updated_at | Date | Date and time the IOC source last updated the IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.requested_expiration | Date | Expiration date and time for this IOC in UTC. | 
| Cofense.IOC.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.IOC.metadata.quarantine.expires_at | Date | Date and time, in UTC, after which this IOC expires. | 
| Cofense.IOC.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.first_quarantined_at | Date | Date and time cofense vision quarantined the first email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.last_quarantined_at | Date | Date and time cofense vision quarantined the last email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.quarantine_count | Number | Number of recipients who received emails matching the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. |
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Description | String | A description of the malicious domain. | 
| Domain.Malicious.Vendor | String | The vendor who reported the domain as malicious. | 
| URL.Data | String | The URL. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| URL.Malicious.Vendor | String | The vendor who reported the URL as malicious. | 
| Email.Address | String | The sender of the email. | 
| Email.Malicious.Description | String | A description of the malicious email. | 
| Email.Malicious.Vendor | String | The vendor who reported the email as malicious. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| File.Malicious.Vendor | String | The vendor who reported the file as malicious. | 

#### Command example
```!cofense-iocs-list source="Vision-UI" size=2```
#### Context Example
```json
{
    "Cofense": {
        "IOC": [
            {
                "attributes": {
                    "threat_type": "DOMAIN",
                    "threat_value": "qwe"
                },
                "id": "088dc5454129d776b4a1484b71bb71b0",
                "metadata": {
                    "quarantine": {
                        "created_at": "2022-07-29T07:09:39.849+00:00",
                        "expired": false,
                        "expires_at": "2022-08-12T07:09:39.849+00:00",
                        "match_count": 0,
                        "quarantine_count": 0,
                        "source_names": [
                            "Vision-UI"
                        ],
                        "wildcard": false
                    },
                    "source": {
                        "created_at": "2022-07-29T00:00:00.000+00:00",
                        "id": "e3026f0c154395767993f34cc71b13e3",
                        "requested_expiration": "2022-08-12T07:09:39.849+00:00",
                        "threat_level": "very_high",
                        "updated_at": "2022-07-29T00:00:00.000+00:00"
                    }
                },
                "type": "ioc"
            },
            {
                "attributes": {
                    "threat_type": "DOMAIN",
                    "threat_value": "fgh"
                },
                "id": "1627363590bae65d9497e0e02bc412b4",
                "metadata": {
                    "quarantine": {
                        "created_at": "2022-08-03T09:20:26.808+00:00",
                        "expired": false,
                        "expires_at": "2022-08-17T09:20:26.808+00:00",
                        "match_count": 0,
                        "quarantine_count": 0,
                        "source_names": [
                            "Vision-UI"
                        ],
                        "wildcard": false
                    },
                    "source": {
                        "created_at": "2022-02-02T00:00:00.000+00:00",
                        "id": "709d185bd891a61dedbcea8040a24a95",
                        "requested_expiration": "2022-08-17T09:20:26.808+00:00",
                        "threat_level": "High",
                        "updated_at": "2022-08-03T00:00:00.000+00:00"
                    }
                },
                "type": "ioc"
            }
        ]
    }
}
```

#### Human Readable Output

>### IOC:
>|ID|Threat Type|Threat Value|Threat Level|Updated At|Created At|Match Count|Quarantine Count|
>|---|---|---|---|---|---|---|---|
>| 088dc5454129d776b4a1484b71bb71b0 | DOMAIN | qwe | very_high | 29/07/2022, 07:09 AM UTC | 29/07/2022, 07:09 AM UTC | 0 | 0 |

>### IOC:
>|ID|Threat Type|Threat Value|Threat Level|Updated At|Created At|Match Count|Quarantine Count|
>|---|---|---|---|---|---|---|---|
>| 1627363590bae65d9497e0e02bc412b4 | DOMAIN | fgh | High | 02/08/2022, 09:20 AM UTC | 03/08/2022, 09:20 AM UTC | 0 | 0 |


### cofense-ioc-update
***
Updates the IOC identified by its unique MD5 ID.


#### Base Command

`cofense-ioc-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the IOC to be updated.<br/><br/>Note: Users can get the list of IDs by executing the "cofense-iocs-list" command. | Required | 
| expires_at | Expiration date and time of the IOC. The timestamp is in UTC.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>Example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.IOC.id | String | MD5 hash composed of the UTF-8 concatenation of "threat_type" and "threat_value" attributes. | 
| Cofense.IOC.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.IOC.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.IOC.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.IOC.metadata.source.threat_level | String | String that describes the severity of the threat. | 
| Cofense.IOC.metadata.source.id | String | Unique identifier assigned by the IOC source. | 
| Cofense.IOC.metadata.source.created_at | Date | Date and time the IOC source included the IOC for the first time. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.updated_at | Date | Date and time the IOC source last updated the IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.requested_expiration | Date | Expiration date and time for this IOC in UTC. | 
| Cofense.IOC.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.IOC.metadata.quarantine.expires_at | Date | Date and time, in UTC, after which this IOC expires. | 
| Cofense.IOC.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.first_quarantined_at | Date | Date and time cofense vision quarantined the first email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.last_quarantined_at | Date | Date and time cofense vision quarantined the last email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.quarantine_count | Number | Number of recipients who received emails matching the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| Cofense.IOC.metadata.quarantine.wildcard | Boolean | Whether the wildcard matching is set \(true\) or not \(false\). | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. |
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Description | String | A description of the malicious domain. | 
| Domain.Malicious.Vendor | String | The vendor who reported the domain as malicious. | 
| URL.Data | String | The URL. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| URL.Malicious.Vendor | String | The vendor who reported the URL as malicious. | 
| Email.Address | String | The sender of the email. | 
| Email.Malicious.Description | String | A description of the malicious email. | 
| Email.Malicious.Vendor | String | The vendor who reported the email as malicious. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| File.Malicious.Vendor | String | The vendor who reported the file as malicious. | 

#### Command example
```!cofense-ioc-update id="bb78c7a2f8c9eea5b9c5a30eb8c9069b" expires_at="1 day"```
#### Context Example
```json
{
    "Cofense": {
        "IOC": {
            "attributes": {
                "threat_type": "DOMAIN",
                "threat_value": "test.com"
            },
            "id": "bb78c7a2f8c9eea5b9c5a30eb8c9069b",
            "metadata": {
                "quarantine": {
                    "created_at": "2022-08-08T09:17:11.188+00:00",
                    "expired": false,
                    "expires_at": "2022-08-24T04:25:24.909+00:00",
                    "match_count": 0,
                    "quarantine_count": 0,
                    "source_names": [
                        "Vision-UI"
                    ],
                    "wildcard": false
                },
                "source": null
            },
            "type": "ioc"
        }
    }
}
```

#### Human Readable Output

>### IOC with value bb78c7a2f8c9eea5b9c5a30eb8c9069b has been updated successfully.
>|ID|Threat Type|Threat Value|Created At|Expires At|
>|---|---|---|---|---|
>| bb78c7a2f8c9eea5b9c5a30eb8c9069b | DOMAIN | test.com | 08/08/2022, 09:17 AM UTC | 24/08/2022, 04:25 AM UTC |


### cofense-iocs-update
***
Updates one or more IOCs stored in the local IOC repository. 
To update multiple IOCs use iocs_json argument.

Note: iocs_json parameter will take precedence over other parameters. 
threat_type, threat_value, threat_level, created_at and source_id 
are required parameters to update a single IOC.


#### Base Command

`cofense-iocs-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | A single IOC source value, to fetch the IOCs added or modified <br/>by that particular source. The value for source can contain <br/>uppercase letters, lowercase letters, numbers, and certain <br/>special characters ("." , "-" , "_" , "~").<br/><br/>Example: "Traige-1" or "IOC_Source-2". | Required | 
| iocs_json | List of JSON data containing ioc details to be updated in the IOC local repository.<br/><br/>Supported format:<br/>\[\{<br/>  "threat_type": "Domain",<br/>  "threat_value":"test1.com",<br/>  "threat_level": "Malicious",<br/>  "created_at":"20/08/2022",<br/>  "source_id":"test_source_1",<br/>  "updated_at": "20/08/2022",<br/>  "requested_expiration": "30/08/2022"<br/>\},<br/>\{<br/>  "threat_type": "Domain",<br/>  "threat_value":"test2.com",<br/>  "threat_level": "Malicious",<br/>  "created_at":"20/08/2022",<br/>  "source_id":"test_source_2",<br/>  "updated_at": "20/08/2022",<br/>  "requested_expiration": "30/08/2022"<br/>\}\]<br/><br/>Note: threat_type, threat_value, threat_level, created_at and source_id are required parameters. | Optional | 
| threat_type | Type of the IOC. <br/><br/>Supported values: Domain, MD5, Sender, SHA256, Subject, or URL. Possible values are: Domain, MD5, Sender, SHA256, Subject, URL. | Optional | 
| threat_value | The actual value of the IOC match in the email. | Optional | 
| threat_level | The severity of the IOC.  <br/><br/>Example: "Malicious". | Optional | 
| source_id | The unique identifier assigned by the IOC source. <br/><br/>Example: source1_id_00001. | Optional | 
| created_at | The UTC date and time, the IOC source included the IOC for the first time.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>Example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z. | Optional | 
| updated_at | The UTC date and time, the IOC source last updated the IOC.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>Example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z<br/><br/>Default value will be the current UTC time.<br/>. | Optional | 
| requested_expiration | The expected UTC expiration date and time. The IOC repository<br/>calculates an expiration date and time for the new IOC by default 14 days<br/>after the IOC is delivered to the IOC repository.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>Example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.IOC.id | String | MD5 hash composed of the UTF-8 concatenation of "threat_type" and "threat_value" attributes. | 
| Cofense.IOC.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.IOC.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.IOC.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.IOC.metadata.source.threat_level | String | String that describes the severity of the threat. | 
| Cofense.IOC.metadata.source.id | String | Unique identifier assigned by the IOC source. | 
| Cofense.IOC.metadata.source.created_at | Date | Date and time the IOC source included the IOC for the first time. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.updated_at | Date | Date and time the IOC source last updated the IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.requested_expiration | Date | Expiration date and time for this IOC in UTC. | 
| Cofense.IOC.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.IOC.metadata.quarantine.expires_at | Date | Date and time, in UTC, after which this IOC expires. | 
| Cofense.IOC.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.first_quarantined_at | Date | Date and time cofense vision quarantined the first email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.last_quarantined_at | Date | Date and time cofense vision quarantined the last email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.quarantine_count | Number | Number of recipients who received emails matching the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| Cofense.IOC.metadata.quarantine.wildcard | Boolean | Whether the wildcard matching is set \(true\) or not \(false\). | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. |
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Description | String | A description of the malicious domain. | 
| Domain.Malicious.Vendor | String | The vendor who reported the domain as malicious. | 
| URL.Data | String | The URL. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| URL.Malicious.Vendor | String | The vendor who reported the URL as malicious. | 
| Email.Address | String | The sender of the email. | 
| Email.Malicious.Description | String | A description of the malicious email. | 
| Email.Malicious.Vendor | String | The vendor who reported the email as malicious. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| File.Malicious.Vendor | String | The vendor who reported the file as malicious. | 

#### Command example
```!cofense-iocs-update source="Vision-UI" iocs_json="[{\"threat_type\":\"Domain\",\"threat_value\":\"test.com\",\"threat_level\":\"Malicious\",\"source_id\":\"test\",\"created_at\":\"1 day\",\"updated_at\":\"1 day\"}]"```
#### Context Example
```json
{
    "Cofense": {
        "IOC": {
            "attributes": {
                "threat_type": "DOMAIN",
                "threat_value": "test.com"
            },
            "id": "bb78c7a2f8c9eea5b9c5a30eb8c9069b",
            "metadata": {
                "quarantine": {
                    "created_at": "2022-08-08T09:17:11.188+00:00",
                    "expired": false,
                    "expires_at": "2022-08-24T04:25:24.909+00:00",
                    "match_count": 0,
                    "quarantine_count": 0,
                    "source_names": [
                        "Vision-UI"
                    ],
                    "wildcard": false
                },
                "source": {
                    "created_at": "2022-08-09T04:25:23.000+00:00",
                    "id": "test",
                    "requested_expiration": "2022-08-24T04:25:24.909+00:00",
                    "threat_level": "Malicious",
                    "updated_at": "2022-08-09T04:25:23.000+00:00"
                }
            },
            "type": "ioc"
        }
    }
}
```

#### Human Readable Output

>### IOC bb78c7a2f8c9eea5b9c5a30eb8c9069b updated successfully.
>|ID|Threat Type|Threat Value|Threat Level|Created At|Updated At|Requested Expiration|
>|---|---|---|---|---|---|---|
>| bb78c7a2f8c9eea5b9c5a30eb8c9069b | DOMAIN | test.com | Malicious | 09/08/2022, 04:25 AM UTC | 09/08/2022, 04:25 AM UTC | 24/08/2022, 04:25 AM UTC |


### cofense-last-ioc-get
***
Synchronizes the update of data between the IOC source and the IOC repository. Retrieves the last updated IOC from the local IOC Repository. It may return an active or an expired IOC.


#### Base Command

`cofense-last-ioc-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | A single IOC source value, to fetch the IOCs added or modified <br/>by that particular source. The value for source can contain <br/>uppercase letters, lowercase letters, numbers, and certain <br/>special characters ("." , "-" , "_" , "~").<br/><br/>Example: "Traige-1" or "IOC_Source-2". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.IOC.id | String | MD5 hash composed of the UTF-8 concatenation of "threat_type" and "threat_value" attributes. | 
| Cofense.IOC.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.IOC.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.IOC.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.IOC.metadata.source.threat_level | String | String that describes the severity of the threat. | 
| Cofense.IOC.metadata.source.id | String | Unique identifier assigned by the IOC source. | 
| Cofense.IOC.metadata.source.created_at | Date | Date and time the IOC source included the IOC for the first time. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.updated_at | Date | Date and time the IOC source last updated the IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.requested_expiration | Date | Expiration date and time for this IOC in UTC. | 
| Cofense.IOC.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.IOC.metadata.quarantine.expires_at | Date | Date and time, in UTC, after which this IOC expires. | 
| Cofense.IOC.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.first_quarantined_at | Date | Date and time cofense vision quarantined the first email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.last_quarantined_at | Date | Date and time cofense vision quarantined the last email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.quarantine_count | Number | Number of recipients who received emails matching the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| Cofense.IOC.metadata.quarantine.wildcard | Boolean | Whether the wildcard matching is set \(true\) or not \(false\). | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. |
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Description | String | A description of the malicious domain. | 
| Domain.Malicious.Vendor | String | The vendor who reported the domain as malicious. | 
| URL.Data | String | The URL. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| URL.Malicious.Vendor | String | The vendor who reported the URL as malicious. | 
| Email.Address | String | The sender of the email. | 
| Email.Malicious.Description | String | A description of the malicious email. | 
| Email.Malicious.Vendor | String | The vendor who reported the email as malicious. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| File.Malicious.Vendor | String | The vendor who reported the file as malicious. | 

#### Command example
```!cofense-last-ioc-get source="Vision-UI"```
#### Context Example
```json
{
    "Cofense": {
        "IOC": {
            "attributes": {
                "threat_type": "SUBJECT",
                "threat_value": "test-subject"
            },
            "id": "bb931fec9d9672a9e307456133223b2e",
            "metadata": {
                "quarantine": {
                    "created_at": "2022-08-10T04:12:49.003+00:00",
                    "expired": false,
                    "expires_at": "2022-08-24T18:29:59.999+00:00",
                    "first_quarantined_at": "2022-08-10T04:12:49.424+00:00",
                    "last_quarantined_at": "2022-08-10T04:12:49.424+00:00",
                    "match_count": 1,
                    "quarantine_count": 10,
                    "source_names": [
                        "Vision-UI"
                    ],
                    "wildcard": false
                },
                "source": {
                    "created_at": "2022-08-10T04:12:45.064+00:00",
                    "id": " ",
                    "requested_expiration": "2022-08-24T18:29:59.999+00:00",
                    "threat_level": "Low",
                    "updated_at": "2022-08-10T04:12:45.064+00:00"
                }
            },
            "type": "ioc"
        }
    }
}
```

#### Human Readable Output

>### Last IOC:
>|ID|Threat Type|Threat Value|Created At|Expires At|Match Count|Quarantine Count|First Quarantined At|Last Quarantined At|
>|---|---|---|---|---|---|---|---|---|
>| bb931fec9d9672a9e307456133223b2e | SUBJECT | test\-subject | 10/08/2022, 04:12 AM UTC | 24/08/2022, 06:29 PM UTC | 1 | 10 | 10/08/2022, 04:12 AM UTC | 10/08/2022, 04:12 AM UTC |


### cofense-ioc-delete
***
Deletes a single active or expired IOC from the local IOC Repository.


#### Base Command

`cofense-ioc-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | A single IOC source value, to fetch the IOCs added or modified <br/>by that particular source. The value for source can contain <br/>uppercase letters, lowercase letters, numbers, and certain <br/>special characters ("." , "-" , "_" , "~").<br/><br/>Example: "Traige-1" or "IOC_Source-2". | Required | 
| id | The ID of the IOC to be deleted.<br/><br/>Note: Users can get the list of IDs by executing the "cofense-iocs-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.IOC.id | String | MD5 hash composed of the UTF-8 concatenation of "threat type" and "threat value" attributes. | 
| Cofense.IOC.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.IOC.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.IOC.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.IOC.metadata.source.threat_level | String | The threat level of the IOC. | 
| Cofense.IOC.metadata.source.id | String | Unique identifier assigned by the IOC source. | 
| Cofense.IOC.metadata.source.created_at | Date | Date and time the IOC source was first seen. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.updated_at | Date | Date and time the IOC source last updated the IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.requested_expiration | Date | Expiration date and time for this IOC in UTC. | 
| Cofense.IOC.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.IOC.metadata.quarantine.expires_at | Date | Date and time, in UTC, after which this IOC expires. | 
| Cofense.IOC.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.first_quarantined_at | Date | Date and time the cofense vision quarantined the email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.last_quarantined_at | Date | Date and time the cofense vision last quarantined the email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.quarantine_count | Number | Number of times the email was quarantined. | 
| Cofense.IOC.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| Cofense.IOC.deleted | Boolean | Indicates whether the IOC is deleted or not. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. |
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Description | String | A description of the malicious domain. | 
| Domain.Malicious.Vendor | String | The vendor who reported the domain as malicious. | 
| URL.Data | String | The URL. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| URL.Malicious.Vendor | String | The vendor who reported the URL as malicious. | 
| Email.Address | String | The sender of the email. | 
| Email.Malicious.Description | String | A description of the malicious email. | 
| Email.Malicious.Vendor | String | The vendor who reported the email as malicious. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| File.Malicious.Vendor | String | The vendor who reported the file as malicious. | 

#### Command example
```!cofense-ioc-delete source="Vision-UI" id=bb931fec9d9672a9e307456133223b2e```
#### Context Example
```json
{
    "Cofense": {
        "IOC": {
            "attributes": {
                "threat_type": "SUBJECT",
                "threat_value": "test-subject"
            },
            "deleted": true,
            "id": "bb931fec9d9672a9e307456133223b2e",
            "metadata": {
                "quarantine": {
                    "created_at": "2022-08-10T04:12:49.003+00:00",
                    "expired": false,
                    "expires_at": "2022-08-24T18:29:59.999+00:00",
                    "first_quarantined_at": "2022-08-10T04:12:49.424+00:00",
                    "last_quarantined_at": "2022-08-10T04:12:49.424+00:00",
                    "match_count": 1,
                    "quarantine_count": 10,
                    "source_names": [
                        "Vision-UI"
                    ],
                    "wildcard": false
                },
                "source": {
                    "created_at": "2022-08-10T04:12:45.064+00:00",
                    "id": " ",
                    "requested_expiration": "2022-08-24T18:29:59.999+00:00",
                    "threat_level": "Low",
                    "updated_at": "2022-08-10T04:12:45.064+00:00"
                }
            },
            "type": "ioc"
        }
    }
}
```

#### Human Readable Output

>###  IOC with value "bb931fec9d9672a9e307456133223b2e" has been deleted successfully.
>|ID|Threat Type|Threat Value|Action Status|
>|---|---|---|---|
>| bb931fec9d9672a9e307456133223b2e | SUBJECT | test\-subject | Success |

### cofense-ioc-get
***
Retrieves the IOC identified by its unique MD5 ID.


#### Base Command

`cofense-ioc-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | A single IOC source value, to fetch the IOCs added or modified <br/>by that particular source. The value for source can contain <br/>uppercase letters, lowercase letters, numbers, and certain <br/>special characters ("." , "-" , "_" , "~").<br/><br/>Example: "Traige-1" or "IOC_Source-2". | Optional | 
| id | The ID of the IOC.<br/><br/>Note: Users can get the list of IDs by executing the "cofense-iocs-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.IOC.id | String | MD5 hash composed of the UTF-8 concatenation of "threat_type" and "threat_value" attributes. | 
| Cofense.IOC.type | String | Type of the cofense resource which is always "ioc". | 
| Cofense.IOC.attributes.threat_type | String | Threat type of the IOC match. | 
| Cofense.IOC.attributes.threat_value | String | Actual value of the IOC match in the email. | 
| Cofense.IOC.metadata.source.threat_level | String | String that describes the severity of the threat. | 
| Cofense.IOC.metadata.source.id | String | Unique identifier assigned by the IOC source. | 
| Cofense.IOC.metadata.source.created_at | Date | Date and time the IOC source included the IOC for the first time. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.updated_at | Date | Date and time the IOC source last updated the IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.source.requested_expiration | Date | Expiration date and time for this IOC in UTC. | 
| Cofense.IOC.metadata.quarantine.source_names | Unknown | Array containing the IOC sources. | 
| Cofense.IOC.metadata.quarantine.expires_at | Date | Date and time, in UTC, after which this IOC expires. | 
| Cofense.IOC.metadata.quarantine.created_at | Date | Date and time the quarantine data was created in the IOC repository. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.first_quarantined_at | Date | Date and time cofense vision quarantined the first email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.last_quarantined_at | Date | Date and time cofense vision quarantined the last email due to this IOC. The timestamp is in UTC. | 
| Cofense.IOC.metadata.quarantine.match_count | Number | Number of unique emails that matched the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.quarantine_count | Number | Number of recipients who received emails matching the IOC while the IOC was active. | 
| Cofense.IOC.metadata.quarantine.expired | Boolean | Whether the IOC is expired \(true\) or not expired \(false\). | 
| Cofense.IOC.metadata.quarantine.wildcard | Boolean | Whether the wildcard matching is set \(true\) or not \(false\). |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. |
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Description | String | A description of the malicious domain. | 
| Domain.Malicious.Vendor | String | The vendor who reported the domain as malicious. | 
| URL.Data | String | The URL. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| URL.Malicious.Vendor | String | The vendor who reported the URL as malicious. | 
| Email.Address | String | The sender of the email. | 
| Email.Malicious.Description | String | A description of the malicious email. | 
| Email.Malicious.Vendor | String | The vendor who reported the email as malicious. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| File.Malicious.Vendor | String | The vendor who reported the file as malicious. | 

#### Command example
```!cofense-ioc-get source="Vision-UI" id=bb931fec9d9672a9e307456133223b2e```
#### Context Example
```json
{
    "Cofense": {
        "IOC": {
            "id": "0c7aff000d37b4a600eb676a473fa5b1",
            "type": "ioc",
            "attributes": {
                "threat_type": "DOMAIN",
                "threat_value": "test"
            },
            "metadata": {
                "source": {
                    "threat_level": "minor",
                    "id": "test",
                    "created_at": "2022-12-09T00:00:00.000+00:00",
                    "updated_at": "2022-09-12T06:55:56.000+00:00",
                    "requested_expiration": "2022-09-26T06:55:57.305+00:00"
                },
                "quarantine": {
                    "source_names": [
                        "Vision-UI"
                    ],
                    "expires_at": "2022-09-26T06:55:57.305+00:00",
                    "created_at": "2022-09-12T06:55:57.305+00:00",
                    "first_quarantined_at": null,
                    "last_quarantined_at": null,
                    "match_count": 0,
                    "quarantine_count": 0,
                    "expired": false,
                    "wildcard": false
                }
            }
        }
    }
}
```

#### Human Readable Output

>### IOC:
>|ID|Threat Type|Threat Value|Created At|Expires At|
>|---|---|---|---|---|
>| 0c7aff000d37b4a600eb676a473fa5b1 | DOMAIN | test | 12/09/2022, 06:55 AM UTC | 26/09/2022, 06:55 AM UTC |

### cofense-searchable-headers-get
***
Retrieves a list of configured header keys that can be used to create a message search.


#### Base Command

`cofense-searchable-headers-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Config.name | String | Name of the configuration which is 'searchableHeaders'. | 
| Cofense.Config.value | Unknown | List of headers that are available to create a message search. | 

#### Command example
```!cofense-searchable-headers-get```
#### Context Example
```json
{
    "Cofense": {
        "Config": {
            "name": "searchableHeaders",
            "value": [
                "X-MS-Exchange-Organization-AuthSource"
            ]
        }
    }
}
```

#### Human Readable Output

>### Available headers to create a search:
>|Headers|
>|---|
>| X-MS-Exchange-Organization-AuthSource |
