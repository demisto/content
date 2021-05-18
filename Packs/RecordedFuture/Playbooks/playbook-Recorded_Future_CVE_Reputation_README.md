CVE reputation with Recorded Future SOAR Enrichment

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts. Depends on the recorded futures indicator field; risk rules.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Recorded Future v2

### Scripts
This playbook does not use any scripts.

### Commands
* cve

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| CVE | The CVE ID to get reputation of. | CVE.ID | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Type | Indicator type | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |
| CVE.ID | Vulnerability name | string |
| RecordedFuture.CVE.riskLevel | Recorded Future Vulnerability Risk Level | string |
| RecordedFuture.CVE.riskScore | Risk Score | number |
| RecordedFuture.CVE.Evidence.rule | Recorded Risk Rule Name | string |
| RecordedFuture.CVE.Evidence.mitigation | Recorded Risk Rule Mitigation | string |
| RecordedFuture.CVE.Evidence.description | Recorded Risk Rule description | string |
| RecordedFuture.CVE.Evidence.timestamp | Recorded Risk Rule timestamp | date |
| RecordedFuture.CVE.Evidence.level | Recorded Risk Rule Level | number |
| RecordedFuture.CVE.Evidence.ruleid | Recorded Risk Rule ID | string |
| RecordedFuture.CVE.name | Vulnerability name | string |
| RecordedFuture.CVE.maxRules | Maximum count of Recorded Future Vulnerability Risk Rules | number |
| RecordedFuture.CVE.ruleCount | Number of triggered Recorded Future Vulnerability Risk Rules | number |

## Playbook Image
---
![Recorded Future CVE Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/cve_reputation.png)
