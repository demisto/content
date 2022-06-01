Use this playbook as a sub-playbook to configure a report and download it.
This playbook implements polling by continuously running the `nexpose-get-report-status` command until the operation completes.
The remote action should have the following structure:

1. Initiate the operation - insert the type of the report (sites, scan, or assets) and it's additional arguments if required.
2. Poll to check if the operation completed.
3. Get the results of the operation.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Rapid7_Nexpose

### Scripts
This playbook does not use any scripts.

### Commands
* nexpose-create-scan-report
* nexpose-download-report
* nexpose-create-sites-report
* nexpose-create-assets-report

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| report_type | \`sites\`, \`scan\`, or \`assets\`. |  | Required |
| sites | Multiple criteria of integer&amp;lt;int32&amp;gt; Site ids to create the report on, comma-separated. |  | Optional |
| assets | Multiple criteria of integer&amp;lt;int64&amp;gt; Asset ids to create the report on, comma-separated. |  | Optional |
| scan | integer &amp;lt;int64&amp;gt; The identifier of the scan. |  | Optional |
| name |  The report name. |  | Optional |
| template | Report template id to create the report with. If none is provided, the first template available will be used. |  | Optional |
| format | The report format. Default is pdf. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| InfoFile.EntryId | Entry Id of the report file | string |
| InfoFile.Name | Name of the report file | string |
| InfoFile.Extension | File extension of the report file | string |
| InfoFile.Info | Info about the report file | string |
| InfoFile.Size | Size of the report file | number |
| InfoFile.Type | Type of the report file | string |

## Playbook Image
---
![Nexpose - Create and download a report](./../doc_files/Nexpose_-_Create_and_download_a_report.png)