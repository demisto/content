Files information using the Virus Total Private API integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.  

### Integrations
* VirusTotal - Private API

### Scripts
This playbook does not use any scripts.

### Commands
* vt-private-get-file-report
* vt-private-check-file-behaviour

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
| File | The file's object. | unknown |
| DBotScore.Indicator | The tested indicator. | string |
| File.SHA1 | The SHA1 hash of the file. | string |
| File.SHA256 | The SHA256 hash of the file. | string |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious.| string |
| File.MD5 | The MD5 hash of the file. | string |
| DBotScore | The DBotScore's object. | unknown |
| DBotScore.Type | The type of the indicator. | string |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| File.VirusTotal.Scans | The scan object. | unknown |
| File.VirusTotal.Scans.Source | The scan vendor for this hash. | unknown |
| File.VirusTotal.Scans.Detected | The scan detection for this hash. Can be, "True" or "False". | unknown |
| File.VirusTotal.Scans.Result | The scan result for this hash. For example, signature, etc. | unknown |

## Playbook Image
---
![File_Enrichment_Virus_Total_Private_API](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/File_Enrichment_Virus_Total_Private_API.png)
