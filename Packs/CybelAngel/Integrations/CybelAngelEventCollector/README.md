CybelAngel receives reports from the CybelAngel platform, which specializes in external attack surface protection and management

## Configure CybelAngel in Cortex


| **Parameter**                                                     | **Required** |
|-------------------------------------------------------------------|--------------|
| Server URL                                                        | True         |
| Client ID                                                         | True         |
| Client Secret                                                     | True         |
| First fetch timestamp (number, time unit, e.g., 12 hours, 7 days) | False        |
| The maximum number of events per fetch                            | True         |
| Trust any certificate (not secure)                                | False        |
| Use system proxy settings                                         | False        |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cybelangel-get-events

***
Send events from CybelAngel to XSIAM. Used mainly for debugging.

#### Base Command

`cybelangel-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Get reports from a specific start date. | Optional | 
| end_date | Get reports until a specific end date. If not provided, uses current date. | Optional | 

#### Context Output

There is no context output for this command.
### cybelangel-report-status-update

***
Update the status of one or multiple reports.

#### Base Command

`cybelangel-report-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_ids | List of report IDs to update. | Required | 
| status | The new status of the reports. Possible values are: draft, open, in_progress, resolved, discarded. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cybelangel-report-status-update report_ids=1234 status=open```
#### Human Readable Output

>"The status of the following reports </report list> has been successfully updated to </report status>."

### cybelangel-report-get

***
Retrieve reports from CybelAngel.

#### Base Command

`cybelangel-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report to retrieve. | Required | 
| pdf | If true, retrieves the report as a PDF file. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report | unknown | The retrieved report. | 
| InfoFile.EntryID | String | Entry ID of the saved PDF file. | 

#### Command example
```!cybelangel-report-get report_id=1234```
#### Context Example
```json
{
    "CybelAngel": {
        "Report": {
            "abstract": "Example Output.",
            "abuse_email": "",
            "analysis": "Example Output.",
            "asset_urls": [],
            "attachments": [
                {
                    "attached_to": "report_id",
                    "id": "1234",
                    "name": "Example Output.csv"
                }
            ],
            "board": "",
            "category": "leak",
            "city": "",
            "country_code": "",
            "created_at": "2000-11-26T13:25:16.116453",
            "detected_at": "2000-11-26T10:45:05+00:00",
            "domain_registered_at": null,
            "hostnames": [],
            "id": "1234",
            "incident_id": "1234",
            "incident_type": "Test",
            "investigation_id": "1234:1234",
            "ip": "",
            "keywords": [
                {
                    "id": "1234",
                    "name": "aa.net"
                }
            ],
            "liveness": {
                "last_checked_at": "2000-11-26T13:25:15.716702+00:00",
                "online": true
            },
            "location": "",
            "machine_name": null,
            "malware_location": null,
            "malware_name": null,
            "module": "account_Test",
            "mx_servers": [],
            "ns_servers": [],
            "origins": [
                {
                    "type": "malicious_actor",
                    "value": ""
                }
            ],
            "port": null,
            "registrant_email": "",
            "registrar_name": "",
            "report_content": "Example Output.",
            "report_type": "incident_detection",
            "risks": [
                {
                    "message": "Example Output.",
                    "type": "account_takeover"
                },
                {
                    "message": "Example Output.",
                    "type": "spear_phishing"
                },
                {
                    "message": "Example Output.",
                    "type": "social_engineering"
                }
            ],
            "samples": [
                {
                    "sample": "See attachment",
                    "type": "other"
                }
            ],
            "screenshots": [],
            "sender": "Example Output@cybelangel.com",
            "sender_tenant_id": "cybelangel",
            "sent_at": "20200-11-26T13:25:57+00:00",
            "severity": 1,
            "source": "Example platform",
            "status": "resolved",
            "stream": "1234",
            "suggestions": [
                {
                    "message": "Example Output.",
                    "type": "other"
                }
            ],
            "tags": [],
            "threat": null,
            "title": "Example Output. platform",
            "updated_at": "2000-02-23T13:07:17.214040",
            "url": "https://platform.cybelangel.com/reports/1234",
            "user_session": null,
            "usergroups": [
                "Example Output.",
                "TVMExample Output.SOC"
            ],
            "volume": {
                "bins": null,
                "documents": null,
                "domain": null,
                "emails": 1,
                "ips": null,
                "passwords": 1
            },
            "whois": ""
        }
    }
}
```

#### Human Readable Output

### Report ID example-id-6 details
|id|report_type|sender|severity|status|updated_at|
|---|---|---|---|---|---|
| example-id-6 | incident_detection | example@example.com | 1 | in_progress | 2025-03-03T09:13:33.253781 |



#### Command example
```!cybelangel-report-get report_id=1234 pdf=true```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1234",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "cybelangel_report_1234.pdf",
        "Size": 127719,
        "Type": "PDF document, version 1.4"
    }
}
```

#### Human Readable Output

>Returned file: cybelangel_report_1234.pdf


### cybelangel-report-remediation-request-create

***
Create a remediation request for a report.

#### Base Command

`cybelangel-report-remediation-request-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report. | Required | 
| requestor_email | Email of the requestor. | Required | 
| requestor_fullname | Full name of the requestor. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cybelangel-report-remediation-request-create report_id=1234 requestor_email=test@paloaltonetworks.com requestor_fullname="Example Test"```
#### Context Example
```json
{
    "CybelAngel": {
        "Report": {
            "RemediationRequest": {
                "report_id": "1234"
            }
        }
    }
}
```

#### Human Readable Output

>Remediation request was created for 1234.

### cybelangel-report-attachment-get

***
Retrieve an attachment from a report.

#### Base Command

`cybelangel-report-attachment-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report. | Required | 
| attachment_id | The ID of the attachment. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | unknown | Entry ID of the retrieved file. | 

#### Command example
```!cybelangel-report-attachment-get report_id=1234 attachment_id=5678```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1111",
        "Extension": "csv",
        "Info": "text/csv; charset=utf-8",
        "Name": "cybelangel_report_1234_attachment_5678.csv",
        "Size": 210,
        "Type": "ASCII text"
    }
}
```

#### Human Readable Output



### cybelangel-archive-report-by-id-get

***
Retrieve an archived report by ID as a ZIP file.

#### Base Command

`cybelangel-archive-report-by-id-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the archived report. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | unknown | Entry ID of the saved ZIP file. | 

#### Command example
```!cybelangel-archive-report-by-id-get report_id=1234```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1111",
        "Extension": "zip",
        "Info": "application/zip",
        "Name": "cybelangel_archive_report_1234.zip",
        "Size": 15604,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

#### Human Readable Output



### cybelangel-mirror-report-get

***
Retrieve the mirror details for the specified report.

#### Base Command

`cybelangel-mirror-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report. | Required | 
| csv | If true, retrieves the mirror report in CSV format. Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.ReportMirror | unknown | Mirror details of the report. | 
| InfoFile.EntryID| unknown | Entry ID of the saved CSV file. | 

#### Command example
```!cybelangel-mirror-report-get report_id=1234```
#### Context Example
```json
{
    "CybelAngel": {
        "ReportMirror": {
            "available_files_count": 1,
            "created_at": "2000-07-11T12:50:20Z",
            "files_count": 1,
            "files_volume": 6871,
            "report_id": "1234",
            "status": "expired",
            "stream_id": "1234",
            "updated_at": "2000-01-12T03:26:49Z"
        }
    }
}
```

#### Human Readable Output

### Mirror details for Report ID example-id-7
|report_id|created_at|available_files_count|updated_at|
|---|---|---|---|
| example-id-7 | 2024-07-11T12:50:20Z | 1 | 2025-01-12T03:26:49Z |


#### Command example
```!cybelangel-mirror-report-get report_id=1234 csv=true```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1111",
        "Extension": "csv",
        "Info": "text/csv; charset=utf-8",
        "Name": "cybelangel_mirror_report_1234.csv",
        "Size": 212,
        "Type": "ASCII text"
    }
}
```

#### Human Readable Output



### cybelangel-report-comment-create

***
Create a new comment on a report.

#### Base Command

`cybelangel-report-comment-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| discussion_id | The discussion_id is made of report id and tenant id like uuid:uuid. Example: [report_id]:[your-tenant-id]. | Required | 
| content | The content of the comment. | Required | 
| parent_id | The ID of the parent comment (for replies). | Optional | 
| assigned | Specifies if the comment is assigned to analysts (true/false). | Optional | 

#### Context Output

There is no context output for this command.

#### Command example
```!cybelangel-report-comment-create report_id=1234 content="Test Comment"```

#### Human Readable Output

>Comment added to Report ID 1234.

### cybelangel-report-list

***
Retrieve reports from CybelAngel.

#### Base Command

`cybelangel-report-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Get reports from a specific start date formatted with ISO 8601. | Optional | 
| end_date | Get reports until a specific end date formatted with ISO 8601. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report | unknown | The retrieved reports. | 

#### Command example
```!cybelangel-report-list start_date="19 hours ago" end_date="now"```
#### Context Example
```json
{
    "CybelAngel": {
        "Report": {
            "reports": [
                {
            "abstract": "Example Output.",
            "abuse_email": "",
            "analysis": "Example Output.",
            "asset_urls": [],
            "attachments": [
                {
                    "attached_to": "report_id",
                    "id": "1234",
                    "name": "Example Output.csv"
                }
            ],
            "board": "",
            "category": "leak",
            "city": "",
            "country_code": "",
            "created_at": "2000-11-26T13:25:16.116453",
            "detected_at": "2000-11-26T10:45:05+00:00",
            "domain_registered_at": null,
            "hostnames": [],
            "id": "1234",
            "incident_id": "1234",
            "incident_type": "Test",
            "investigation_id": "1234:1234",
            "ip": "",
            "keywords": [
                {
                    "id": "1234",
                    "name": "aa.net"
                }
            ],
            "liveness": {
                "last_checked_at": "2000-11-26T13:25:15.716702+00:00",
                "online": true
            },
            "location": "",
            "machine_name": null,
            "malware_location": null,
            "malware_name": null,
            "module": "account_Test",
            "mx_servers": [],
            "ns_servers": [],
            "origins": [
                {
                    "type": "malicious_actor",
                    "value": ""
                }
            ],
            "port": null,
            "registrant_email": "",
            "registrar_name": "",
            "report_content": "Example Output.",
            "report_type": "incident_detection",
            "risks": [
                {
                    "message": "Example Output.",
                    "type": "account_takeover"
                },
                {
                    "message": "Example Output.",
                    "type": "spear_phishing"
                },
                {
                    "message": "Example Output.",
                    "type": "social_engineering"
                }
            ],
            "samples": [
                {
                    "sample": "See attachment",
                    "type": "other"
                }
            ],
            "screenshots": [],
            "sender": "Example Output@cybelangel.com",
            "sender_tenant_id": "cybelangel",
            "sent_at": "20200-11-26T13:25:57+00:00",
            "severity": 1,
            "source": "Example platform",
            "status": "resolved",
            "stream": "1234",
            "suggestions": [
                {
                    "message": "Example Output.",
                    "type": "other"
                }
            ],
            "tags": [],
            "threat": null,
            "title": "Example Output. platform",
            "updated_at": "2000-02-23T13:07:17.214040",
            "url": "https://platform.cybelangel.com/reports/1234",
            "user_session": null,
            "usergroups": [
                "Example Output.",
                "TVMExample Output.SOC"
            ],
            "volume": {
                "bins": null,
                "documents": null,
                "domain": null,
                "emails": 1,
                "ips": null,
                "passwords": 1
            },
            "whois": ""
        },
        {
            "abstract": "Example Output.",
            "abuse_email": "",
            "analysis": "Example Output.",
            "asset_urls": [],
            "attachments": [
                {
                    "attached_to": "report_id",
                    "id": "1234",
                    "name": "Example Output.csv"
                }
            ],
            "board": "",
            "category": "leak",
            "city": "",
            "country_code": "",
            "created_at": "2000-11-26T13:25:16.116453",
            "detected_at": "2000-11-26T10:45:05+00:00",
            "domain_registered_at": null,
            "hostnames": [],
            "id": "1234",
            "incident_id": "1234",
            "incident_type": "Test",
            "investigation_id": "1234:1234",
            "ip": "",
            "keywords": [
                {
                    "id": "1234",
                    "name": "aa.net"
                }
            ],
            "liveness": {
                "last_checked_at": "2000-11-26T13:25:15.716702+00:00",
                "online": true
            },
            "location": "",
            "machine_name": null,
            "malware_location": null,
            "malware_name": null,
            "module": "account_Test",
            "mx_servers": [],
            "ns_servers": [],
            "origins": [
                {
                    "type": "malicious_actor",
                    "value": ""
                }
            ],
            "port": null,
            "registrant_email": "",
            "registrar_name": "",
            "report_content": "Example Output.",
            "report_type": "incident_detection",
            "risks": [
                {
                    "message": "Example Output.",
                    "type": "account_takeover"
                },
                {
                    "message": "Example Output.",
                    "type": "spear_phishing"
                },
                {
                    "message": "Example Output.",
                    "type": "social_engineering"
                }
            ],
            "samples": [
                {
                    "sample": "See attachment",
                    "type": "other"
                }
            ],
            "screenshots": [],
            "sender": "Example Output@cybelangel.com",
            "sender_tenant_id": "cybelangel",
            "sent_at": "20200-11-26T13:25:57+00:00",
            "severity": 1,
            "source": "Example platform",
            "status": "resolved",
            "stream": "1234",
            "suggestions": [
                {
                    "message": "Example Output.",
                    "type": "other"
                }
            ],
            "tags": [],
            "threat": null,
            "title": "Example Output. platform",
            "updated_at": "2000-02-23T13:07:17.214040",
            "url": "https://platform.cybelangel.com/reports/1234",
            "user_session": null,
            "usergroups": [
                "Example Output.",
                "TVMExample Output.SOC"
            ],
            "volume": {
                "bins": null,
                "documents": null,
                "domain": null,
                "emails": 1,
                "ips": null,
                "passwords": 1
            },
            "whois": ""
        }
            ]
        }
    }
}
```

#### Human Readable Output

### Reports list
|id|url|report_type|sender|severity|status|updated_at|report_content|
|---|---|---|---|---|---|---|---|
| example-id-1 | https://platform.example.com/reports/example-id-1 | incident_detection | example@example.com | 1 | open | 2025-02-25T13:06:06.821922 | ### Sample content… Example |
| example-id-2 | https://platform.example.com/reports/example-id-2 | incident_detection | example@example.com | 1 | resolved | 2025-02-26T18:58:50.303598 | ### Sample content… Example |
| example-id-3 | https://platform.example.com/reports/example-id-3 | incident_detection | example@example.com | 1 | in_progress | 2025-02-26T12:17:42.241832 | ### Sample content… Example |
| example-id-4 | https://platform.example.com/reports/example-id-4 | incident_detection | example@example.com | 1 | open | 2025-02-26T13:29:54.520708 | ### Sample content… Example |
| example-id-5 | https://platform.example.com/reports/example-id-5 | incident_detection | example@example.com | 2 | open | 2025-02-25T16:29:32.696281 | ### Sample content… Example |
| example-id-6 | https://platform.example.com/reports/example-id-6 | incident_detection | example@example.com | 1 | in_progress | 2025-03-03T09:13:33.253781 | ### Sample content… Example |
| example-id-7 | https://platform.example.com/reports/example-id-7 | incident_detection | example@example.com | 1 | in_progress | 2025-03-03T09:13:33.253781 | ### Sample content… Example |
| example-id-8 | https://platform.example.com/reports/example-id-8 | incident_detection | example@example.com | 1 | open | 2025-03-03T14:26:11.424002 | ### Sample content… Example |
| example-id-9 | https://platform.example.com/reports/example-id-9 | incident_detection | example@example.com | 1 | open | 2025-03-03T14:22:14.184243 | ### Sample content… Example |
| example-id-10 | https://platform.example.com/reports/example-id-10 | incident_detection | example@example.com | 1 | open | 2025-03-03T14:28:22.089922 | ### Sample content… Example |


### cybelangel-report-comments-get

***
Retrieve comments from a report.

#### Base Command

`cybelangel-report-comments-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybelAngel.Report.Comment | unknown | The list of comments for the report. | 

#### Command example
```!cybelangel-report-comments-get report_id=1234```
#### Context Example
```json
{
    "CybelAngel": {
        "Report": {
            "Comments": {
                "comments": [
                    {
                        "assigned": false,
                        "author": {
                            "firstname": "Example",
                            "id": "1234",
                            "lastname": "Test"
                        },
                        "content": "Test Comment 2",
                        "created_at": "2000-07-11T15:29:05Z",
                        "discussion_id": "1234:5678",
                        "discussion_tenant_name": "Test",
                        "id": "1234",
                        "isNew": false,
                        "last_updated_at": "2000-07-11T15:29:05Z"
                    },
                    {
                        "assigned": false,
                        "author": {
                            "firstname": "Example",
                            "id": "1234",
                            "lastname": "Test"
                        },
                        "content": "Test Comment 2",
                        "created_at": "2000-07-11T15:29:05Z",
                        "discussion_id": "1234:5678",
                        "discussion_tenant_name": "Test",
                        "id": "1234",
                        "isNew": false,
                        "last_updated_at": "2000-07-11T15:29:05Z"
                    }
                ],
                "new": 0,
                "total": 2,
                "id": "1234"
            }
        }
    }
}
```

#### Human Readable Output

### Comments for Report ID example-id-8
|content|created_at|discussion_id|assigned|author_firstname|author_lastname|last_updated_at|
|---|---|---|---|---|---|---|
| This is a comment message | 2025-02-27T11:04:05Z | example-id-8:example-tenant-id | false | ExampleFirst | ExampleLast | 2025-02-27T11:04:05Z |
