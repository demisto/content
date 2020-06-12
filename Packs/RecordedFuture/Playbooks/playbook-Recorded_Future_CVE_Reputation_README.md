CVE reputation with Recorded Future SOAR Enrichment

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

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
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| CVE.ID | Vulnerability name | unknown |
| RecordedFuture.CVE.riskLevel | Recorded Future Vulnerability Risk Level | unknown |
| RecordedFuture.CVE.riskScore | Risk Score | unknown |
| RecordedFuture.CVE.Evidence.rule | Recorded Risk Rule Name | unknown |
| RecordedFuture.CVE.Evidence.mitigation | Recorded Risk Rule Mitigation | unknown |
| RecordedFuture.CVE.Evidence.description | Recorded Risk Rule description | unknown |
| RecordedFuture.CVE.Evidence.timestamp | Recorded Risk Rule timestamp | unknown |
| RecordedFuture.CVE.Evidence.level | Recorded Risk Rule Level | unknown |
| RecordedFuture.CVE.Evidence.ruleid | Recorded Risk Rule ID | unknown |
| RecordedFuture.CVE.name | Vulnerability name | unknown |
| RecordedFuture.CVE.maxRules | Maximum count of Recorded Future Vulnerability Risk Rules | unknown |
| RecordedFuture.CVE.ruleCount | Number of triggered Recorded Future Vulnerability Risk Rules | unknown |

## Playbook Image
---
![Recorded Future CVE Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/cve_reputation.png)