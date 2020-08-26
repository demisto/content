DEPRECATED. Use "File Enrichment - Generic v2" playbook instead. Enriches a file using one or more integrations.

File enrichment includes:
* File history
* Threat information
* File reputation

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* File Enrichment - File reputation
* File Enrichment - Virus Total private API

### Integrations
* Cylance Protect v2

### Scripts
This playbook does not use any scripts.

### Commands
* cylance-protect-get-threat

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| MD5 | The MD5 hash to enrich. | MD5 | File | Optional |
| SHA256 | The SHA256 hash to enrich. | SHA256 | File | Optional |
| SHA1 | The SHA1 hash to enrich. | SHA1 | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The tested indicator. | string |
| DBotScore.Type | The type of the indicator. | string |
| File.SHA1 | The SHA1 hash of the file. | string |
| File.SHA256 | The SHA256 hash of the file. | string |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | string |
| File.MD5 | The MD5 hash of the file. | string |
| DBotScore | The DBotScore's object. | unknown |
| File | The file's object. | unknown |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| File.VirusTotal.Scans | The scan object. | unknown |
| File.VirusTotal.Scans.Source | The scan vendor for this hash. | unknown |
| File.VirusTotal.Scans.Detected | The scan detection for this hash. Can be, "True" or "False". | unknown |
| File.VirusTotal.Scans.Result | The scan result for this hash. For example, signature, etc. | unknown |

## Playbook Image
---
![File_Enrichment_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/File_Enrichment_Generic.png)
