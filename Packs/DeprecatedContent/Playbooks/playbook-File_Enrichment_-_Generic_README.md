Deprecated. Use "File Enrichment - Generic v2" playbook instead. Enrich a file using one or more integrations.

File enrichment includes:
* File history
* Threat information
* File reputation

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* File Enrichment - Virus Total private API
* File Enrichment - File reputation

### Integrations
* Cylance Protect v2

### Scripts
This playbook does not use any scripts.

### Commands
* cylance-protect-get-threat

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | File MD5 hash to enrich. | File.MD5 | Optional |
| SHA256 | File SHA-256 hash to enrich. | File.SHA256 | Optional |
| SHA1 | File SHA-1 hash to enrich. | File.SHA1 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The tested indicator | string |
| DBotScore.Type | The type of the indicator | string |
| File.SHA1 | SHA1 hash of the file | string |
| File.SHA256 | SHA256 hash of the file | string |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision | string |
| File.MD5 | MD5 hash of the file | string |
| DBotScore | The DBotScore's object | unknown |
| File | The file's object | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |
| File.VirusTotal.Scans | the scan object | unknown |
| File.VirusTotal.Scans.Source | Scan vendor for this hash | unknown |
| File.VirusTotal.Scans.Detected | Scan detection for this hash \(True,False\) | unknown |
| File.VirusTotal.Scans.Result | Scan result for this hash - signature, etc. | unknown |

## Playbook Image
---
![File Enrichment - Generic](Insert the link to your image here)