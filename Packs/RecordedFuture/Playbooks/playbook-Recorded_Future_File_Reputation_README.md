File reputation using Recorded Future SOAR Enrichment

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Recorded Future v2

### Scripts
This playbook does not use any scripts.

### Commands
* file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | File MD5 hash to get reputation of. | File.MD5 | Optional |
| SHA256 | File SHA\-256 hash to get reputation of. | File.SHA256 | Optional |
| SHA1 | File SHA\-1 hash to get reputation of. | File.SHA1 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.SHA256 | File SHA\-256 | unknown |
| File.SHA512 | File SHA\-512 | unknown |
| File.SHA1 | File SHA\-1 | unknown |
| File.MD5 | File MD5 | unknown |
| File.CRC32 | File CRC32 | unknown |
| File.CTPH | File CTPH | unknown |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision | unknown |
| File.Malicious.Description | For malicious files, the reason that the vendor made the decision | unknown |
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| RecordedFuture.File.riskScore | Recorded Future Hash Risk Score | unknown |
| RecordedFuture.File.riskLevel | Recorded Future Hash Risk Level | unknown |
| RecordedFuture.File.Evidence.rule | Recorded Risk Rule Name | unknown |
| RecordedFuture.File.Evidence.mitigation | Recorded Risk Rule Mitigation | unknown |
| RecordedFuture.File.Evidence.description | Recorded Risk Rule description | unknown |
| RecordedFuture.File.Evidence.timestamp | Recorded Risk Rule timestamp | unknown |
| RecordedFuture.File.Evidence.level | Recorded Risk Rule Level | unknown |
| RecordedFuture.File.Evidence.ruleid | Recorded Risk Rule ID | unknown |
| RecordedFuture.File.name | Hash | unknown |
| RecordedFuture.File.maxRules | Maximum count of Recorded Future Hash Risk Rules | unknown |
| RecordedFuture.File.ruleCount | Number of triggered Recorded Future Hash Risk Rules | unknown |

## Playbook Image
---
![Recorded Future File Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/file_reputation.png)