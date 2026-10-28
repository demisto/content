Detonates a URL using the TrendAI™ Deep Discovery™ Analyzer sandbox.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* Trend Micro Deep Discovery Analyzer

### Scripts

This playbook does not use any scripts.

### Commands

* trendmicro-dda-check-status
* trendmicro-dda-get-report
* trendmicro-dda-upload-url

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | URL to detonate. | URL.Data | Required |
| interval | Polling frequency - how often the polling command should run \(minutes\) | 1 | Optional |
| timeput | How much time to wait before a timeout occurs \(minutes\) | 15 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| InfoFile.Type | Report file type e.g. "PE" | string |
| InfoFile.SHA256 | SHA256 hash of the report  file | string |
| TrendMicroDDA.Submissions.SHA1 | The SHA1 of the submission | string |
| TrendMicroDDA.Submissions.RiskLevel | The Risk Level of the sample | number |
| DBotScore.Score | The actual score | number |
| TrendMicroDDA.Submissions.isCompleted | Stating if the detonation was complete or not | string |
| DBotScore.Indicator | The indicator we tested | string |
| TrendMicroDDA.Submissions.status | The status of the sample | string |
| DBotScore.Type | The type of the indicator | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| InfoFile.MD5 | MD5 hash of the report file | string |
| InfoFile.Name | Report file name | string |
| InfoFile.Size | Report file size  | number |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision | string |
| File.Malicious.Description | For malicious files, the reason for the vendor to make the decision | string |
| IP.Address | IPs relevant to the submission | string |
| Domain.Name | Domains relevant to the submission | string |
| URL.Data | URL data | string |
| File.MD5 | MD5 hash of the file | string |
| File.SHA1 | SHA1 hash of the file | string |
| File.SHA256 | SHA256 hash of the file | string |
| File.Size | File size | number |
| File.Name | File name | string |

## Playbook Image

---

![Detonate URL - Trend Micro Deep Discovery Analyzer Beta](../doc_files/TrendMicro_DDA_DetonateURL.png)
