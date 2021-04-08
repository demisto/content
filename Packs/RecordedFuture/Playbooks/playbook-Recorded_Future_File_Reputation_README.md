File reputation using Recorded Future SOAR Enrichment

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts. Depends on the recorded futures indicator field; risk rules.

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
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Type | Indicator type | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |
| File.SHA256 | File SHA\-256 | string |
| File.SHA512 | File SHA\-512 | string |
| File.SHA1 | File SHA\-1 | string |
| File.MD5 | File MD5 | string |
| File.CRC32 | File CRC32 | string |
| File.CTPH | File CTPH | string |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision | string |
| File.Malicious.Description | For malicious files, the reason that the vendor made the decision | string |
| RecordedFuture.File.riskScore | Recorded Future Hash Risk Score | number |
| RecordedFuture.File.riskLevel | Recorded Future Hash Risk Level | string |
| RecordedFuture.File.Evidence.rule | Recorded Risk Rule Name | string |
| RecordedFuture.File.Evidence.mitigation | Recorded Risk Rule Mitigation | string |
| RecordedFuture.File.Evidence.description | Recorded Risk Rule description | string |
| RecordedFuture.File.Evidence.timestamp | Recorded Risk Rule timestamp | date |
| RecordedFuture.File.Evidence.level | Recorded Risk Rule Level | number |
| RecordedFuture.File.Evidence.ruleid | Recorded Risk Rule ID | string |
| RecordedFuture.File.name | Hash | string |
| RecordedFuture.File.maxRules | Maximum count of Recorded Future Hash Risk Rules | number |
| RecordedFuture.File.ruleCount | Number of triggered Recorded Future Hash Risk Rules | number |

## Playbook Image
---
![Recorded Future File Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/file_reputation.png)
