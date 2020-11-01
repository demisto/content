Use the Cofense Triage integration to ingest reported phishing indicators.
This integration was integrated and tested with version 1.20 of Cofense Triage v2
## Configure Cofense Triage v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cofense Triage v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| host | Server URL \(e.g., https://192.168.0.1\) | True |
| user | User | True |
| token | API Token | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| date_range | First fetch time \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| category_id | Category ID to fetch | False |
| match_priority | Match Priority \- the highest match priority based on rule hits for the report | False |
| tags | Tags \- CSV list of tags of processed reports by which to filter  | False |
| max_fetch | Maximum number of incidents to fetch each time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cofense-search-reports
***
Runs a query for reports.


#### Base Command

`cofense-search-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | File hash, MD5 or SHA256. | Optional | 
| url | The reported URLs. | Optional | 
| subject | Report's subject | Optional | 
| reported_at | Retrieve reports that were reported after this time, for example: "2 hours, 4 minutes, 6 month, 1 day". | Optional | 
| created_at | Retrieve reports that were created after this time, for example: "2 hours, 4 minutes, 6 month, 1 day". | Optional | 
| reporter | Address or ID of the reporter. | Optional | 
| max_matches | Maximum number of matches to fetch. Default is 30. | Optional | 
| verbose | Returns all fields of a report. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Report.ID | unknown | ID number of the report. | 
| Cofense.Report.EmailAttachments | unknown | Email attachments. | 
| Cofense.Report.EmailAttachments.id | unknown | Email attachment ID. | 
| Cofense.Report.Tags | string | Report tags. | 
| Cofense.Report.ClusterId | number | Cluster ID number. | 
| Cofense.Report.CategoryId | number | Report category. | 
| Cofense.Report.CreatedAt | date | Report creation date. | 
| Cofense.Report.ReportedAt | string | Reporting time. | 
| Cofense.Report.MatchPriority | number | The highest match priority based on rule hits for the report. | 
| Cofense.Report.ReporterId | number | Reporter ID. | 
| Cofense.Report.Location | string | Location of the report. | 
| Cofense.Report.Reporter | string | Reporter email address. | 
| Cofense.Report.SuspectFromAddress | string | Suspect from address. | 
| Cofense.Report.ReportSubject | string | Report subject. | 
| Cofense.Report.ReportBody | string | Report body. | 
| Cofense.Report.Md5 | number | MD5 hash of the file. | 
| Cofense.Report.Sha256 | unknown | SHA256 hash of the file. | 


#### Command Example
```!cofense-search-reports reported_at="7 days" created_at="7 days" max_matches="1"```

#### Context Example
```
{
    "Cofense": {
        "Report": {
            "CategoryId": 4,
            "ClusterId": null,
            "CreatedAt": "2020-06-04T13:42:26.173Z",
            "EmailAttachments": [
                {
                    "content_type": "image/png; name=image001.png",
                    "decoded_filename": "image001.png",
                    "email_attachment_payload": {
                        "id": 7095,
                        "md5": "5008fb6e6652f56cac5bdc5bf1cbe9c2",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "554aeaaace31c7038a09dd408945583e1035ec124a46b04e5c6c5b148dc96f68"
                    },
                    "id": 18087,
                    "report_id": 13429,
                    "size_in_bytes": 1397
                },
                {
                    "content_type": "image/png; name=image003.png",
                    "decoded_filename": "image003.png",
                    "email_attachment_payload": {
                        "id": 7097,
                        "md5": "731ffb7846c22e41e9de8de307c93ece",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "c911d07d1f7be624e00e44821148629d98cf6d0f2bfac112362c7c564522ea51"
                    },
                    "id": 18089,
                    "report_id": 13429,
                    "size_in_bytes": 1701
                },
                {
                    "content_type": "image/png; name=image006.png",
                    "decoded_filename": "image006.png",
                    "email_attachment_payload": {
                        "id": 7100,
                        "md5": "124bd437f87181fdfe3154b31fd2cf6b",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "3d804c705545bf2a1e5ac6b0ea9b93a41ceb16d7453adebc58fba5df75335b20"
                    },
                    "id": 18092,
                    "report_id": 13429,
                    "size_in_bytes": 1994
                },
                {
                    "content_type": "image/png; name=image002.png",
                    "decoded_filename": "image002.png",
                    "email_attachment_payload": {
                        "id": 7096,
                        "md5": "cc07463ceeaaed79783a7f2a607797f9",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "c6c2c95238f52648faaef4520fa9bba49c10ca0f1df9bfd1912be544f319b80b"
                    },
                    "id": 18088,
                    "report_id": 13429,
                    "size_in_bytes": 1430
                },
                {
                    "content_type": "image/png; name=image004.png",
                    "decoded_filename": "image004.png",
                    "email_attachment_payload": {
                        "id": 7098,
                        "md5": "95878e37974ed3cad67154d36dd58a9a",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "e0d478f6ce56721867a0584ddea0016d713b9b2ab758fd0c9be3f1409d6e2634"
                    },
                    "id": 18090,
                    "report_id": 13429,
                    "size_in_bytes": 1557
                },
                {
                    "content_type": "image/png; name=image005.png",
                    "decoded_filename": "image005.png",
                    "email_attachment_payload": {
                        "id": 7099,
                        "md5": "0e911498bf4dc5eddb544ab5ece4b06a",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "5f2046b3c55a874aadde052f9da4af3c17e2b5bf5baf704f58b1dd1eadf08544"
                    },
                    "id": 18091,
                    "report_id": 13429,
                    "size_in_bytes": 1609
                },
                {
                    "content_type": "application/pdf; name=\"XSOAR Attachment Test -Inquiry - Agent Tesla Keylogger.pdf\"",
                    "decoded_filename": "XSOAR Attachment Test -Inquiry - Agent Tesla Keylogger.pdf",
                    "email_attachment_payload": {
                        "id": 7110,
                        "md5": "fb7f083f4fb93a88ab8110d857312978",
                        "mime_type": "application/pdf; charset=binary",
                        "sha256": "15ab1b20ada04dfc6285caff5e4da4eab09a9157c2cbe32cd96113da6304a5ee"
                    },
                    "id": 18093,
                    "report_id": 13429,
                    "size_in_bytes": 49597
                }
            ],
            "ID": 13429,
            "Location": "Processed",
            "MatchPriority": 1,
            "Md5": "d312e79695d5de744436006aab6b4ec1",
            "ReportBody": "Testing PDF attachment\r\n\r\n\r\nTest User  |  Director\r\nTEST\r\nm. 123-456-7890\r\ne. test@test.com<mailto:test@test.com>\r\n\r\nConnect with Cofense:\r\n\r\n[signature_527626984]<https://cofense.com/>[signature_379086648]<https://facebook.com/cofense>[signature_426568440]<https://twitter.com/cofense>[signature_1467413640]<https://linkedin.com/company/cofense>[signature_749445379]<https://www.instagram.com/cofense/>[signature_1384270593]<https://www.themuse.com/profiles/cofense>\r\n\r\nUniting Humanity Against Phishing. Watch Our Video<https://cofense.com/project/uhap-video/>\r\n\r\n",
            "ReportSubject": "2020-06-04 XSOAR attachment test",
            "ReportedAt": "2020-06-04T13:40:29.000Z",
            "ReporterId": 5331,
            "Sha256": "ba77b5d984f7da97b6f96daa442535c79f47e4b6ea0055e3472b855ee8c244e4",
            "Tags": []
        }
    }
}
```

#### Human Readable Output

>### Reports:
>|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Body|Report Subject|Reported At|Reporter Id|Sha256|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 4 | 2020-06-04T13:42:26.173Z | {'id': 18087, 'report_id': 13429, 'decoded_filename': 'image001.png', 'content_type': 'image/png; name=image001.png', 'size_in_bytes': 1397, 'email_attachment_payload': {'id': 7095, 'md5': '5008fb6e6652f56cac5bdc5bf1cbe9c2', 'sha256': '554aeaaace31c7038a09dd408945583e1035ec124a46b04e5c6c5b148dc96f68', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18089, 'report_id': 13429, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 1701, 'email_attachment_payload': {'id': 7097, 'md5': '731ffb7846c22e41e9de8de307c93ece', 'sha256': 'c911d07d1f7be624e00e44821148629d98cf6d0f2bfac112362c7c564522ea51', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18092, 'report_id': 13429, 'decoded_filename': 'image006.png', 'content_type': 'image/png; name=image006.png', 'size_in_bytes': 1994, 'email_attachment_payload': {'id': 7100, 'md5': '124bd437f87181fdfe3154b31fd2cf6b', 'sha256': '3d804c705545bf2a1e5ac6b0ea9b93a41ceb16d7453adebc58fba5df75335b20', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18088, 'report_id': 13429, 'decoded_filename': 'image002.png', 'content_type': 'image/png; name=image002.png', 'size_in_bytes': 1430, 'email_attachment_payload': {'id': 7096, 'md5': 'cc07463ceeaaed79783a7f2a607797f9', 'sha256': 'c6c2c95238f52648faaef4520fa9bba49c10ca0f1df9bfd1912be544f319b80b', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18090, 'report_id': 13429, 'decoded_filename': 'image004.png', 'content_type': 'image/png; name=image004.png', 'size_in_bytes': 1557, 'email_attachment_payload': {'id': 7098, 'md5': '95878e37974ed3cad67154d36dd58a9a', 'sha256': 'e0d478f6ce56721867a0584ddea0016d713b9b2ab758fd0c9be3f1409d6e2634', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18091, 'report_id': 13429, 'decoded_filename': 'image005.png', 'content_type': 'image/png; name=image005.png', 'size_in_bytes': 1609, 'email_attachment_payload': {'id': 7099, 'md5': '0e911498bf4dc5eddb544ab5ece4b06a', 'sha256': '5f2046b3c55a874aadde052f9da4af3c17e2b5bf5baf704f58b1dd1eadf08544', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18093, 'report_id': 13429, 'decoded_filename': 'XSOAR Attachment Test -Inquiry - Agent Tesla Keylogger.pdf', 'content_type': 'application/pdf; name="XSOAR Attachment Test -Inquiry - Agent Tesla Keylogger.pdf"', 'size_in_bytes': 49597, 'email_attachment_payload': {'id': 7110, 'md5': 'fb7f083f4fb93a88ab8110d857312978', 'sha256': '15ab1b20ada04dfc6285caff5e4da4eab09a9157c2cbe32cd96113da6304a5ee', 'mime_type': 'application/pdf; charset=binary'}} | 13429 | Processed | 1 | d312e79695d5de744436006aab6b4ec1 | Testing PDF attachment<br/><br/><br/>Test User  \|  Director<br/>COFENSE<br/>m. 123-456-7890<br/>e. test@test.com<mailto:test@test.com><br/><br/>Connect with Cofense:<br/><br/>[signature_527626984]<https://cofense.com/>[signature_379086648]<https://facebook.com/cofense>[signature_426568440]<https://twitter.com/cofense>[signature_1467413640]<https://linkedin.com/company/cofense>[signature_749445379]<https://www.instagram.com/cofense/>[signature_1384270593]<https://www.themuse.com/profiles/cofense><br/><br/>Uniting Humanity Against Phishing. Watch Our Video<https://cofense.com/project/uhap-video/><br/><br/> | 2020-06-04 XSOAR attachment test | 2020-06-04T13:40:29.000Z | 5331 | ba77b5d984f7da97b6f96daa442535c79f47e4b6ea0055e3472b855ee8c244e4 |


### cofense-search-inbox-reports
***
Runs a query for reports from the `inbox` mailbox.


#### Base Command

`cofense-search-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | File hash, MD5 or SHA256. | Optional | 
| url | The reported URLs. | Optional | 
| subject | Report's subject | Optional | 
| reported_at | Retrieve reports that were reported after this time, for example: "2 hours, 4 minutes, 6 month, 1 day". | Optional | 
| created_at | Retrieve reports that were created after this time, for example: "2 hours, 4 minutes, 6 month, 1 day". | Optional | 
| reporter | Address or ID of the reporter. | Optional | 
| max_matches | Maximum number of matches to fetch. Default is 30. | Optional | 
| verbose | Returns all fields of a report. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Report.ID | unknown | ID number of the report. | 
| Cofense.Report.EmailAttachments | unknown | Email attachments. | 
| Cofense.Report.EmailAttachments.id | unknown | Email attachment ID. | 
| Cofense.Report.Tags | string | Report tags. | 
| Cofense.Report.ClusterId | number | Cluster ID number. | 
| Cofense.Report.CategoryId | number | Report category. | 
| Cofense.Report.CreatedAt | date | Report creation date. | 
| Cofense.Report.ReportedAt | string | Reporting time. | 
| Cofense.Report.MatchPriority | number | The highest match priority based on rule hits for the report. | 
| Cofense.Report.ReporterId | number | Reporter ID. | 
| Cofense.Report.Location | string | Location of the report. | 
| Cofense.Report.Reporter | string | Reporter email address. | 
| Cofense.Report.SuspectFromAddress | string | Suspect from address. | 
| Cofense.Report.ReportSubject | string | Report subject. | 
| Cofense.Report.ReportBody | string | Report body. | 
| Cofense.Report.Md5 | number | MD5 hash of the file. | 
| Cofense.Report.Sha256 | unknown | SHA256 hash of the file. | 


#### Command Example
```!cofense-search-inbox-reports reported_at="7 days" created_at="7 days" max_matches="1"```

#### Context Example
```json
{
    "Cofense": {
        "Report": {
            "CategoryId": 4,
            "ClusterId": null,
            "CreatedAt": "2020-06-04T13:42:26.173Z",
            "EmailAttachments": [
                {
                    "content_type": "image/png; name=image001.png",
                    "decoded_filename": "image001.png",
                    "email_attachment_payload": {
                        "id": 7095,
                        "md5": "5008fb6e6652f56cac5bdc5bf1cbe9c2",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "554aeaaace31c7038a09dd408945583e1035ec124a46b04e5c6c5b148dc96f68"
                    },
                    "id": 18087,
                    "report_id": 13429,
                    "size_in_bytes": 1397
                },
                {
                    "content_type": "image/png; name=image003.png",
                    "decoded_filename": "image003.png",
                    "email_attachment_payload": {
                        "id": 7097,
                        "md5": "731ffb7846c22e41e9de8de307c93ece",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "c911d07d1f7be624e00e44821148629d98cf6d0f2bfac112362c7c564522ea51"
                    },
                    "id": 18089,
                    "report_id": 13429,
                    "size_in_bytes": 1701
                },
                {
                    "content_type": "image/png; name=image006.png",
                    "decoded_filename": "image006.png",
                    "email_attachment_payload": {
                        "id": 7100,
                        "md5": "124bd437f87181fdfe3154b31fd2cf6b",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "3d804c705545bf2a1e5ac6b0ea9b93a41ceb16d7453adebc58fba5df75335b20"
                    },
                    "id": 18092,
                    "report_id": 13429,
                    "size_in_bytes": 1994
                },
                {
                    "content_type": "image/png; name=image002.png",
                    "decoded_filename": "image002.png",
                    "email_attachment_payload": {
                        "id": 7096,
                        "md5": "cc07463ceeaaed79783a7f2a607797f9",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "c6c2c95238f52648faaef4520fa9bba49c10ca0f1df9bfd1912be544f319b80b"
                    },
                    "id": 18088,
                    "report_id": 13429,
                    "size_in_bytes": 1430
                },
                {
                    "content_type": "image/png; name=image004.png",
                    "decoded_filename": "image004.png",
                    "email_attachment_payload": {
                        "id": 7098,
                        "md5": "95878e37974ed3cad67154d36dd58a9a",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "e0d478f6ce56721867a0584ddea0016d713b9b2ab758fd0c9be3f1409d6e2634"
                    },
                    "id": 18090,
                    "report_id": 13429,
                    "size_in_bytes": 1557
                },
                {
                    "content_type": "image/png; name=image005.png",
                    "decoded_filename": "image005.png",
                    "email_attachment_payload": {
                        "id": 7099,
                        "md5": "0e911498bf4dc5eddb544ab5ece4b06a",
                        "mime_type": "image/png; charset=binary",
                        "sha256": "5f2046b3c55a874aadde052f9da4af3c17e2b5bf5baf704f58b1dd1eadf08544"
                    },
                    "id": 18091,
                    "report_id": 13429,
                    "size_in_bytes": 1609
                },
                {
                    "content_type": "application/pdf; name=\"XSOAR Attachment Test -Inquiry - Agent Tesla Keylogger.pdf\"",
                    "decoded_filename": "XSOAR Attachment Test -Inquiry - Agent Tesla Keylogger.pdf",
                    "email_attachment_payload": {
                        "id": 7110,
                        "md5": "fb7f083f4fb93a88ab8110d857312978",
                        "mime_type": "application/pdf; charset=binary",
                        "sha256": "15ab1b20ada04dfc6285caff5e4da4eab09a9157c2cbe32cd96113da6304a5ee"
                    },
                    "id": 18093,
                    "report_id": 13429,
                    "size_in_bytes": 49597
                }
            ],
            "ID": 13429,
            "Location": "Inbox",
            "MatchPriority": 1,
            "Md5": "d312e79695d5de744436006aab6b4ec1",
            "ReportBody": "Testing PDF attachment\r\n\r\n\r\nTest User  |  Director\r\nTEST\r\nm. 123-456-7890\r\ne. test@test.com<mailto:test@test.com>\r\n\r\nConnect with Cofense:\r\n\r\n[signature_527626984]<https://cofense.com/>[signature_379086648]<https://facebook.com/cofense>[signature_426568440]<https://twitter.com/cofense>[signature_1467413640]<https://linkedin.com/company/cofense>[signature_749445379]<https://www.instagram.com/cofense/>[signature_1384270593]<https://www.themuse.com/profiles/cofense>\r\n\r\nUniting Humanity Against Phishing. Watch Our Video<https://cofense.com/project/uhap-video/>\r\n\r\n",
            "ReportSubject": "2020-06-04 XSOAR attachment test",
            "ReportedAt": "2020-06-04T13:40:29.000Z",
            "ReporterId": 5331,
            "Sha256": "ba77b5d984f7da97b6f96daa442535c79f47e4b6ea0055e3472b855ee8c244e4",
            "Tags": []
        }
    }
}
```

#### Human Readable Output

>### Reports:
>|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Body|Report Subject|Reported At|Reporter Id|Sha256|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 4 | 2020-06-04T13:42:26.173Z | {'id': 18087, 'report_id': 13429, 'decoded_filename': 'image001.png', 'content_type': 'image/png; name=image001.png', 'size_in_bytes': 1397, 'email_attachment_payload': {'id': 7095, 'md5': '5008fb6e6652f56cac5bdc5bf1cbe9c2', 'sha256': '554aeaaace31c7038a09dd408945583e1035ec124a46b04e5c6c5b148dc96f68', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18089, 'report_id': 13429, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 1701, 'email_attachment_payload': {'id': 7097, 'md5': '731ffb7846c22e41e9de8de307c93ece', 'sha256': 'c911d07d1f7be624e00e44821148629d98cf6d0f2bfac112362c7c564522ea51', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18092, 'report_id': 13429, 'decoded_filename': 'image006.png', 'content_type': 'image/png; name=image006.png', 'size_in_bytes': 1994, 'email_attachment_payload': {'id': 7100, 'md5': '124bd437f87181fdfe3154b31fd2cf6b', 'sha256': '3d804c705545bf2a1e5ac6b0ea9b93a41ceb16d7453adebc58fba5df75335b20', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18088, 'report_id': 13429, 'decoded_filename': 'image002.png', 'content_type': 'image/png; name=image002.png', 'size_in_bytes': 1430, 'email_attachment_payload': {'id': 7096, 'md5': 'cc07463ceeaaed79783a7f2a607797f9', 'sha256': 'c6c2c95238f52648faaef4520fa9bba49c10ca0f1df9bfd1912be544f319b80b', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18090, 'report_id': 13429, 'decoded_filename': 'image004.png', 'content_type': 'image/png; name=image004.png', 'size_in_bytes': 1557, 'email_attachment_payload': {'id': 7098, 'md5': '95878e37974ed3cad67154d36dd58a9a', 'sha256': 'e0d478f6ce56721867a0584ddea0016d713b9b2ab758fd0c9be3f1409d6e2634', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18091, 'report_id': 13429, 'decoded_filename': 'image005.png', 'content_type': 'image/png; name=image005.png', 'size_in_bytes': 1609, 'email_attachment_payload': {'id': 7099, 'md5': '0e911498bf4dc5eddb544ab5ece4b06a', 'sha256': '5f2046b3c55a874aadde052f9da4af3c17e2b5bf5baf704f58b1dd1eadf08544', 'mime_type': 'image/png; charset=binary'}},<br/>{'id': 18093, 'report_id': 13429, 'decoded_filename': 'XSOAR Attachment Test -Inquiry - Agent Tesla Keylogger.pdf', 'content_type': 'application/pdf; name="XSOAR Attachment Test -Inquiry - Agent Tesla Keylogger.pdf"', 'size_in_bytes': 49597, 'email_attachment_payload': {'id': 7110, 'md5': 'fb7f083f4fb93a88ab8110d857312978', 'sha256': '15ab1b20ada04dfc6285caff5e4da4eab09a9157c2cbe32cd96113da6304a5ee', 'mime_type': 'application/pdf; charset=binary'}} | 13429 | Processed | 1 | d312e79695d5de744436006aab6b4ec1 | Testing PDF attachment<br/><br/><br/>Test User  \|  Director<br/>TEST<br/>m. 123-456-7890<br/>e. test@test.com<mailto:test@test.com><br/><br/>Connect with Cofense:<br/><br/>[signature_527626984]<https://cofense.com/>[signature_379086648]<https://facebook.com/cofense>[signature_426568440]<https://twitter.com/cofense>[signature_1467413640]<https://linkedin.com/company/cofense>[signature_749445379]<https://www.instagram.com/cofense/>[signature_1384270593]<https://www.themuse.com/profiles/cofense><br/><br/>Uniting Humanity Against Phishing. Watch Our Video<https://cofense.com/project/uhap-video/><br/><br/> | 2020-06-04 XSOAR attachment test | 2020-06-04T13:40:29.000Z | 5331 | ba77b5d984f7da97b6f96daa442535c79f47e4b6ea0055e3472b855ee8c244e4 |


### cofense-get-attachment
***
Retrieves an attachment by the attachment ID number. 


#### Base Command

`cofense-get-attachment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachment_id | ID of the attachment. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.Type | string | File type, for example: "PE", "txt" | 
| File.EntryID | string | The file entry ID. | 
| File.Name | string | File name. | 
| File.SHA1 | string | File SHA1 hash. | 
| File.SHA256 | string | File SHA256 hash. | 
| File.MD5 | string | File MD5 hash. | 


#### Command Example
```!cofense-get-attachment attachment_id="13311"```

#### Context Example
```
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



### cofense-get-reporter
***
Retrieves Email address of the reporter by ID


#### Base Command

`cofense-get-reporter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reporter_id | ID of the reporter. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Reporter.ID | number | ID of the reporter. | 
| Cofense.Reporter.Email | string | Reporter email address. | 
| Cofense.Reporter.CreatedAt | string | Reporter creation date. | 
| Cofense.Reporter.UpdatedAt | string | Reporter last\-updated date. | 
| Cofense.Reporter.CreditibilityScore | number | Reporter credibility score. | 
| Cofense.Reporter.ReportsCount | number | Number of reports. | 
| Cofense.Reporter.LastReportedAt | string | Date of most recent report. | 
| Cofense.Reporter.VIP | bool | Whether Reporter is a VIP. | 


#### Command Example
```!cofense-get-reporter reporter_id="1"```

#### Context Example
```
{
    "Cofense": {
        "Reporter": {
            "CreatedAt": "2019-04-12T02:58:17.401Z",
            "CredibilityScore": 0,
            "Email": "ha.oullette@example.com",
            "ID": 1,
            "LastReportedAt": "2016-02-18T00:24:45.000Z",
            "ReportsCount": 3,
            "UpdatedAt": "2019-04-12T02:59:22.287Z",
            "Vip": false
        }
    }
}
```

#### Human Readable Output

>Integration log: cmel case attrs: {'ID': 1, 'Email': 'ha.oullette@example.com', 'CreatedAt': '2019-04-12T02:58:17.401Z', 'UpdatedAt': '2019-04-12T02:59:22.287Z', 'CredibilityScore': 0, 'ReportsCount': 3, 'LastReportedAt': '2016-02-18T00:24:45.000Z', 'Vip': False}### Reporter Results:
>|Created At|Credibility Score|Email|Id|Last Reported At|Reports Count|Updated At|Vip|
>|---|---|---|---|---|---|---|---|
>| 2019-04-12T02:58:17.401Z | 0 | ha.oullette@example.com | 1 | 2016-02-18T00:24:45.000Z | 3 | 2019-04-12T02:59:22.287Z | false |


### cofense-get-report-by-id
***
Retrieves a report by the report ID number. 


#### Base Command

`cofense-get-report-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | ID of the report | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.Report.ID | number | ID number of the report. | 
| Cofense.Report.EmailAttachments | string | Email attachments. | 
| Cofense.Report.EmailAttachments.id | string | Email attachment ID. | 
| Cofense.Report.Tags | string | Report tags. | 
| Cofense.Report.ClusterId | number | Cluster ID number. | 
| Cofense.Report.CategoryId | number | Report category. | 
| Cofense.Report.CreatedAt | string | Report creation date. | 
| Cofense.Report.ReportedAt | string | Reporting time. | 
| Cofense.Report.MatchPriority | number | The highest match priority based on rule hits for the report. | 
| Cofense.Report.ReporterId | number | Reporter ID. | 
| Cofense.Report.Location | string | Location of the report. | 
| Cofense.Report.Reporter | string | Reporter email address. | 
| Cofense.Report.SuspectFromAddress | string | Suspect from address. | 
| Cofense.Report.ReportSubject | string | Report subject. | 
| Cofense.Report.ReportBody | string | Report body. | 
| Cofense.Report.Md5 | number | MD5 hash of the file. | 
| Cofense.Report.Sha256 | unknown | SHA256 hash of the file. | 


#### Command Example
```!cofense-get-report-by-id report_id="5760"```

#### Context Example
```
{
    "Cofense": {
        "Report": {
            "CategoryId": 4,
            "ClusterId": null,
            "CreatedAt": "2019-04-17T20:53:02.090Z",
            "EmailAttachments": [],
            "ID": 5760,
            "Location": "Processed",
            "MatchPriority": 0,
            "Md5": "f13bbc172fe7d394828ccabb25c3c99e",
            "ReportSubject": "test@test.net Reset password instruction",
            "ReportedAt": "2019-04-17T16:54:57.000Z",
            "ReporterId": 3280,
            "Sha256": "4f6bc0d9c1217a2a6f327423e16b7a6e9294c68cfb33864541bd805fe4ab2d72",
            "Tags": []
        }
    }
}
```

#### Human Readable Output

>{"HumanReadable":"### Cofense HTML Report:\nHTML report download request has been completed","name":"5760-report.html","path":"aaf1160b-9176-45d9-aab9-90efd278e05d"}### Report Summary:
>|Category Id|Created At|Id|Location|Match Priority|Md5|Report Subject|Reported At|Reporter Id|Sha256|
>|---|---|---|---|---|---|---|---|---|---|
>| 4 | 2019-04-17T20:53:02.090Z | 5760 | Processed | 0 | f13bbc172fe7d394828ccabb25c3c99e | test@test.nul Reset password instruction | 2019-04-17T16:54:57.000Z | 3280 | 4f6bc0d9c1217a2a6f327423e16b7a6e9294c68cfb33864541bd805fe4ab2d72 |


### cofense-get-report-png-by-id
***
Retrieves a report by the report ID number and displays as PNG


#### Base Command

`cofense-get-report-png-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID PNG output | Required | 
| set_white_bg | Change background to white | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cofense-get-report-png-by-id report_id="5760" set_white_bg="True"```

#### Context Example
```
{
    "InfoFile": {
        "EntryID": "616@cc18bdc4-7c64-494c-879c-23c3aee60818",
        "Extension": "png",
        "Info": "image/png",
        "Name": "cofense_report_5760.png",
        "Size": 40692,
        "Type": "PNG image data, 400 x 369, 8-bit/color RGBA, non-interlaced"
    }
}
```

#### Human Readable Output

>Cofense: PNG of Report 5760

### cofense-get-threat-indicators
***
Threat Indicators that are designated by analysts as malicious, suspicious or benign


#### Base Command

`cofense-get-threat-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | indicator type | Optional | 
| level | indicator severity | Optional | 
| start_date | designated start date tagged by analyst (format example: YYYY-MM-DD+HH:MM:SS). Default: 6 days ago. | Optional | 
| end_date | designated end date from assignment (format example: YYYY-MM-DD+HH:MM:SS). Default: current date. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cofense.ThreatIndicators | unknown | Threat indicator output | 
| Cofense.ThreatIndicators.ID | number | Threat indicator ID in Cofense Triage. | 
| Cofense.ThreatIndicators.OperatorId | number | Cofense Triage operator who designated the threat indicator. | 
| Cofense.ThreatIndicators.ReportId | number | Associated Report in Cofense Triage. | 
| Cofense.ThreatIndicators.ThreatKey | string | Threat indicator type. | 
| Cofense.ThreatIndicators.ThreatLevel | string | Threat indicator level. | 
| Cofense.ThreatIndicators.ThreatValue | string | Value of the threat indicator. | 


#### Command Example
```!cofense-get-threat-indicators type="URL" level="Malicious" start_date="2020-05-28"```

#### Context Example
```
{
    "Cofense": {
        "ThreatIndicators": {
            "CreatedAt": "2020-05-28T22:14:52.690Z",
            "ID": 75,
            "OperatorId": 2,
            "ReportId": 5760,
            "ThreatKey": "URL",
            "ThreatLevel": "Malicious",
            "ThreatValue": "http://bold-air0example.com/notification.php?email=test@test.net"
        }
    }
}
```

#### Human Readable Output

>### Threat Indicators:
>|Created At|Id|Operator Id|Report Id|Threat Key|Threat Level|Threat Value|
>|---|---|---|---|---|---|---|
>| 2020-05-28T22:14:52.690Z | 75 | 2 | 5760 | URL | Malicious | `http://bold-air0example.com/notification.php?email=test@test.net` |

