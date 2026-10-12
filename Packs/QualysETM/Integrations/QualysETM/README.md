Manage Qualys Enterprise TruRisk Management (ETM) finding reports. ETM consolidates findings relating to vulnerabilities, misconfigurations, malware, and compliance from multiple sources into a unified view with a risk score (TruRisk Score).
This integration was integrated and tested with version xx of QualysETM.

## Configure Qualys Enterprise TruRisk Management (ETM) in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Qualys API Gateway URL to use for API requests depends on the platform where your account is located.<br/>Platforms and URLs:<br/>Qualys US Platform 1: <https://gateway.qg1.apps.qualys.com><br/>Qualys US Platform 2: <https://gateway.qg2.apps.qualys.com><br/>Qualys US Platform 3: <https://gateway.qg3.apps.qualys.com><br/>Qualys EU Platform 1: <https://gateway.qg1.apps.qualys.eu><br/>Qualys EU Platform 2: <https://gateway.qg2.apps.qualys.eu><br/>Qualys India Platform 1: <https://gateway.qg1.apps.qualys.in><br/>Qualys Private Cloud Platform \(Custom Platform\): https://gateway.&lt;customer_base_url&gt;<br/>To identify your platform, see <https://www.qualys.com/platform-identification/>. | True |
| Username | The Qualys account username and password. The credentials are exchanged for a JSON Web Token \(JWT\) that is used to authenticate the API requests. | True |
| Password |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### qualys-etm-active-reports-list

***
Lists the active reports in the Qualys ETM subscription. To retrieve the full details of a single report, use the qualys-etm-report-get-details command.

#### Base Command

`qualys-etm-active-reports-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. Minimum value is 1. Used together with the page_size argument. | Optional |
| page_size | The number of results to retrieve in a single page. Used together with the page argument. | Optional |
| limit | The maximum number of results to return. Used when the page and page_size arguments are not provided. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysETM.Report.id | String | The unique ID of the report. |
| QualysETM.Report.name | String | The name of the report. |
| QualysETM.Report.status | String | The current status of the report. |
| QualysETM.Report.created | Date | The date and time when the report was created. |
| QualysETM.Report.expirationDate | Date | The date and time when the report expires. |

#### Command example

```!qualys-etm-active-reports-list limit=2```

#### Context Example

```json
{
    "QualysETM": {
        "Report": [
            {
                "created": "2026-10-01T10:00:00Z",
                "expirationDate": "2026-10-08T10:00:00Z",
                "id": "0b127284-e128-4d02-a720-2748240c9f1a",
                "name": "Ad-hoc Report",
                "status": "COMPLETED"
            },
            {
                "created": "2026-10-02T08:30:00Z",
                "expirationDate": "2026-10-09T08:30:00Z",
                "id": "dbc34b32-b957-449a-a357-27cf27df7eab",
                "name": "Weekly Risk Report",
                "status": "REQUESTED"
            }
        ]
    }
}
```

#### Human Readable Output

>### Qualys ETM Active Reports
>
>|Report ID|Name|Status|Created|Expiration Date|
>|---|---|---|---|---|
>| 0b127284-e128-4d02-a720-2748240c9f1a | Ad-hoc Report | COMPLETED | 2026-10-01T10:00:00Z | 2026-10-08T10:00:00Z |
>| dbc34b32-b957-449a-a357-27cf27df7eab | Weekly Risk Report | REQUESTED | 2026-10-02T08:30:00Z | 2026-10-09T08:30:00Z |

### qualys-etm-report-get-details

***
Returns the full details of a single report, including the list of its downloadable resources.

#### Base Command

`qualys-etm-report-get-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The unique ID of the report. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysETM.Report.id | String | The unique ID of the report. |
| QualysETM.Report.name | String | The name of the report. |
| QualysETM.Report.description | String | The description of the report. |
| QualysETM.Report.reportFormat | String | The format of the report. |
| QualysETM.Report.status | String | The current status of the report. |
| QualysETM.Report.assetQql | String | The asset QQL filter that was used to generate the report. |
| QualysETM.Report.findingsQql | String | The findings QQL filter that was used to generate the report. |
| QualysETM.Report.created | Date | The date and time when the report was created. |
| QualysETM.Report.createdBy.name | String | The name of the user who created the report. |
| QualysETM.Report.updated | Date | The date and time when the report was last updated. |
| QualysETM.Report.expirationDate | Date | The date and time when the report expires. |
| QualysETM.Report.resources | Unknown | The names of the downloadable part-files of the report. Available once the report status is COMPLETED. |

#### Command example

```!qualys-etm-report-get-details report_id=0b127284-e128-4d02-a720-2748240c9f1a```

#### Context Example

```json
{
    "QualysETM": {
        "Report": {
            "assetQql": "asset.name: my-host",
            "created": "2026-10-01T10:00:00Z",
            "createdBy": {
                "name": "john_doe"
            },
            "description": "Critical findings report",
            "expirationDate": "2026-10-08T10:00:00Z",
            "findingsQql": "finding.severity: 5",
            "id": "0b127284-e128-4d02-a720-2748240c9f1a",
            "name": "Ad-hoc Report",
            "reportFormat": "JSON",
            "resources": [
                "part_15097524224131306.json",
                "part_15097524224131307.json"
            ],
            "status": "COMPLETED",
            "updated": "2026-10-01T10:05:00Z"
        }
    }
}
```

#### Human Readable Output

>### Qualys ETM Report 0b127284-e128-4d02-a720-2748240c9f1a
>
>|Report ID|Name|Description|Report Format|Status|Asset QQL|Findings QQL|Created|Created By|Updated|Expiration Date|Resources|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0b127284-e128-4d02-a720-2748240c9f1a | Ad-hoc Report | Critical findings report | JSON | COMPLETED | asset.name: my-host | finding.severity: 5 | 2026-10-01T10:00:00Z | john_doe | 2026-10-01T10:05:00Z | 2026-10-08T10:00:00Z | part_15097524224131306.json, part_15097524224131307.json |

### qualys-etm-report-download

***
Downloads a single part-file of a report by its resource name and returns it to the War Room as a file. Use the qualys-etm-report-get-details command to obtain the valid resource names of a completed report.

#### Base Command

`qualys-etm-report-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The unique ID of the report. | Required |
| resource_name | The name of the part-file to download, as listed in the resources field of the report details. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | String | The name of the file. |
| InfoFile.EntryID | String | The entry ID of the file. |
| InfoFile.Size | Number | The size of the file in bytes. |
| InfoFile.Type | String | The type of the file. |
| InfoFile.Extension | String | The extension of the file. |
| InfoFile.Info | String | The information about the file. |

#### Command example

```!qualys-etm-report-download report_id=0b127284-e128-4d02-a720-2748240c9f1a resource_name=part_15097524224131306.json```

#### Context Example

```json
{
    "InfoFile": {
        "EntryID": "1234@abcd-efgh-ijkl-mnop",
        "Extension": "json",
        "Info": "application/json",
        "Name": "part_15097524224131306.json",
        "Size": 4096,
        "Type": "ASCII text"
    }
}
```

#### Human Readable Output

>Uploaded file: part_15097524224131306.json

### qualys-etm-report-generate

***
Submits a new findings report request, polls until the report generation completes, and then downloads all of the report resources as a ZIP file to the War Room. Note that each polling iteration consumes a request from the Qualys rate limit of 300 requests per hour.

#### Base Command

`qualys-etm-report-generate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the report. | Optional |
| description | The description of the report. | Optional |
| report_format | The format of the generated report. Possible values are: JSON, PARQUET. Default is JSON. | Optional |
| asset_qql | A QQL filter that limits the report to the matching assets. For example, "asset.name: my-host". | Optional |
| findings_qql | A QQL filter that limits the report to the matching findings. For example, "finding.severity: 5". | Optional |
| interval_in_seconds | The interval in seconds between each poll of the report status. Default is 10. | Optional |
| timeout_in_seconds | The total time in seconds to wait for the report to complete before the command fails. The report is not deleted on timeout and can be retrieved later using the qualys-etm-report-get-details command. Default is 300. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysETM.Report.id | String | The unique ID of the report. |
| QualysETM.Report.name | String | The name of the report. |
| QualysETM.Report.description | String | The description of the report. |
| QualysETM.Report.reportFormat | String | The format of the report. |
| QualysETM.Report.status | String | The current status of the report. |
| QualysETM.Report.assetQql | String | The asset QQL filter that was used to generate the report. |
| QualysETM.Report.findingsQql | String | The findings QQL filter that was used to generate the report. |
| QualysETM.Report.created | Date | The date and time when the report was created. |
| QualysETM.Report.createdBy.name | String | The name of the user who created the report. |
| QualysETM.Report.updated | Date | The date and time when the report was last updated. |
| QualysETM.Report.expirationDate | Date | The date and time when the report expires. |
| QualysETM.Report.resources | Unknown | The names of the downloadable part-files of the report. |

#### Command example

```!qualys-etm-report-generate name="Critical Findings Report" findings_qql="finding.severity: 5" report_format=JSON```

#### Context Example

```json
{
    "QualysETM": {
        "Report": {
            "assetQql": "asset.name: my-host",
            "created": "2026-10-01T10:00:00Z",
            "createdBy": {
                "name": "john_doe"
            },
            "description": "Critical findings report",
            "expirationDate": "2026-10-08T10:00:00Z",
            "findingsQql": "finding.severity: 5",
            "id": "0b127284-e128-4d02-a720-2748240c9f1a",
            "name": "Ad-hoc Report",
            "reportFormat": "JSON",
            "resources": [
                "part_15097524224131306.json",
                "part_15097524224131307.json"
            ],
            "status": "COMPLETED",
            "updated": "2026-10-01T10:05:00Z"
        }
    }
}
```

#### Human Readable Output

>### Qualys ETM Report 0b127284-e128-4d02-a720-2748240c9f1a
>
>|Report ID|Name|Description|Report Format|Status|Asset QQL|Findings QQL|Created|Created By|Updated|Expiration Date|Resources|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0b127284-e128-4d02-a720-2748240c9f1a | Ad-hoc Report | Critical findings report | JSON | COMPLETED | asset.name: my-host | finding.severity: 5 | 2026-10-01T10:00:00Z | john_doe | 2026-10-01T10:05:00Z | 2026-10-08T10:00:00Z | part_15097524224131306.json, part_15097524224131307.json |

The completed report is also returned to the War Room as the file `report_0b127284-e128-4d02-a720-2748240c9f1a.zip`.

### qualys-etm-reports-delete

***
Deletes one or more reports. To delete a single report, provide its ID as the only value of the report_ids argument.

#### Base Command

`qualys-etm-reports-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_ids | A comma-separated list of the IDs of the reports to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QualysETM.ReportDeletion.reportId | String | The ID of the deleted report. |
| QualysETM.ReportDeletion.message | String | The message returned by Qualys for the deleted report. |

#### Command example

```!qualys-etm-reports-delete report_ids=dbc34b32-b957-449a-a357-27cf27df7eab```

#### Context Example

```json
{
    "QualysETM": {
        "ReportDeletion": [
            {
                "message": "Report deleted successfully",
                "reportId": "dbc34b32-b957-449a-a357-27cf27df7eab"
            }
        ]
    }
}
```

#### Human Readable Output

>### Qualys ETM Deleted Reports
>
>|Report ID|Message|
>|---|---|
>| dbc34b32-b957-449a-a357-27cf27df7eab | Report deleted successfully |
