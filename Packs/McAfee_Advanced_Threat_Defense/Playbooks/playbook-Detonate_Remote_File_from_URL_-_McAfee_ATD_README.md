Detonates a File from a URL using the McAfee Advanced Threat Defense sandbox integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* McAfee_Advanced_Threat_Defense

### Scripts
* Set

### Commands
* atd-get-report
* atd-file-upload
* atd-check-status

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | URL to detonate. | URL.Data | Optional |
| Interval | Polling frequency - how often the polling command should run \(minutes\) | 1 | Optional |
| Timeout | How much time to wait before a timeout occurs \(minutes\) | 15 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ATD.Task.taskId | The task ID of the sample uploaded | string |
| ATD.Task.jobId | The job ID of the sample uploaded | string |
| ATD.Task.messageId | The message Id relevant to the sample uploaded | string |
| ATD.Task.url | The URL detonated | string |
| ATD.Task.srcIp | Source IPv4 address | string |
| ATD.Task.destIp | Destination IPv4 address | string |
| ATD.Task.MD5 | MD5 of the sample uploaded | string |
| ATD.Task.SHA1 | SHA1 of the sample uploaded | string |
| ATD.Task.SHA256 | SHA256 of the sample uploaded | string |
| File.Name | Filename \(only in case of report type=json\) | string |
| File.Type | File type e.g. "PE" \(only in case of report type=json\) | string |
| File.MD5 | MD5 hash of the file \(only in case of report type=json\) | string |
| File.SHA1 | SHA1 hash of the file \(only in case of report type=json\) | string |
| File.SHA256 | SHA256 hash of the file \(only in case of report type=json\) | string |
| File.EntryID | The Entry ID of the sample | string |
| DBotScore.Indicator | The indicator we tested \(only in case of report type=json\) | string |
| DBotScore.Type | The type of the indicator \(only in case of report type=json\) | string |
| DBotScore.Vendor | Vendor used to calculate the score \(only in case of report type=json\) | string |
| DBotScore.Score | The actual score \(only in case of report type=json\) | number |
| IP.Address | IP's relevant to the sample | string |
| InfoFile.EntryID | The EntryID of the report file | string |
| InfoFile.Extension | The extension of the report file | string |
| InfoFile.Name | The name of the report file | string |
| InfoFile.Info | The info of the report file | string |
| InfoFile.Size | The size of the report file | number |
| InfoFile.Type | The type of the report file | string |
| File | File object | unknown |
| File.Malicious | File Malicious object | unknown |
| DBotScore | DBotScore object | unknown |
| InfoFile | Report file object | unknown |
| URL.Malicious | URL Malicious object | unknown |