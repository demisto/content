Detonate one or more files using the Anomali ThreatStream v2 integration. This playbook returns relevant reports to the War Room, and file reputations to the context data.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* AnomaliThreatStreamv3
* Anomali_ThreatStream_v2

### Scripts

* Set

### Commands

* threatstream-submit-to-sandbox
* threatstream-analysis-report

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | File object of the file to detonate. | File | Optional |
| VM | The VM to use \(string\) |  | Optional |
| SubmissionClassification | Classification of the Sandbox submission. |  | Optional |
| PremiumSandbox | Specifies if the premium sandbox should be used for detonation. |  | Optional |
| Tags | A CSV list of tags applied to this sample. |  | Optional |
| Interval | Polling frequency - how often the polling command should run \(minutes\). |  | Optional |
| Timeout | Amount of time to wait before a timeout occurs \(minutes\). |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Malicious | The file malicious description. | unknown |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision. | string |
| File.Type | File type, for example: "PE". | string |
| File.Size | File size. | number |
| File.MD5 | MD5 hash of the file. | string |
| File.Name | File name. | string |
| File.SHA1 | SHA1 hash of the file. | string |
| File | The file object. | unknown |
| File.SHA256 | SHA256 hash of the file. | string |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Indicator | The indicator that was tested. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |

## Playbook Image

---

![Detonate File - ThreatStream](../doc_files/Detonate_File_-_ThreatStream.png)
