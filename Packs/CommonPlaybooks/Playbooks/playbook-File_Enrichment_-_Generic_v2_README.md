Enrich a file using one or more integrations.

- Provide threat information

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* File Enrichment - Virus Total (API v3)

### Integrations

* Cylance Protect v2

### Scripts

This playbook does not use any scripts.

### Commands

* file
* cylance-protect-get-threat

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | File MD5 hash to enrich. | File.MD5 | Optional |
| SHA256 | The file SHA256 hash to enrich. | File.SHA256 | Optional |
| SHA1 | The file SHA1 hash to enrich. | File.SHA1 | Optional |
| UseReputationCommand | Define if you would like to use the \!file command.<br/>Note: This input should be used whenever there is no auto-extract enabled in the investigation flow.<br/>Possible values: True / False. | False | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested. | string |
| DBotScore.Type | The indicator type. | string |
| File.SHA1 | SHA1 hash of the file. | string |
| File.SHA256 | SHA256 hash of the file. | string |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision. | string |
| File.MD5 | MD5 hash of the file. | string |
| DBotScore | The DBotScore object. | unknown |
| File | The file object | unknown |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| File.VirusTotal.Scans | The scan object. | unknown |
| File.VirusTotal.Scans.Source | Vendor that scanned this hash. | unknown |
| File.VirusTotal.Scans.Detected | Whether a scan was detected for this hash \(True/False\). | unknown |
| File.VirusTotal.Scans.Result | Scan result for this hash - signature, etc. | unknown |

## Playbook Image

---

![File Enrichment - Generic v2](../doc_files/File_Enrichment_-_Generic_v2.png)
