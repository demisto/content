Domain reputation using Recorded Future SOAR Enrichment

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Recorded Future v2

### Scripts
This playbook does not use any scripts.

### Commands
* domain

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The domain name to get reputation of. | Domain.Name | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| Domain.Malicious.Vendor | For malicious Domains, the vendor that made the decision | unknown |
| Domain.Malicious.Description | For malicious Domains, the reason that the vendor made the decision | unknown |
| Domain.name | Domain name | unknown |
| RecordedFuture.Domain.riskScore | Recorded Future Domain Risk Score | unknown |
| RecordedFuture.Domain.riskLevel | Recorded Future Domain Risk Level | unknown |
| RecordedFuture.Domain.Evidence.rule | Recorded Risk Rule Name | unknown |
| RecordedFuture.Domain.Evidence.mitigation | Recorded Risk Rule Mitigation | unknown |
| RecordedFuture.Domain.Evidence.description | Recorded Risk Rule description | unknown |
| RecordedFuture.Domain.Evidence.timestamp | Recorded Risk Rule timestamp | unknown |
| RecordedFuture.Domain.Evidence.level | Recorded Risk Rule Level | unknown |
| RecordedFuture.Domain.Evidence.ruleid | Recorded Risk Rule ID | unknown |
| RecordedFuture.Domain.name | Domain name | unknown |
| RecordedFuture.Domain.maxRules | Maximum count of Recorded Future Domain Risk Rules | unknown |
| RecordedFuture.Domain.ruleCount | Number of triggered Recorded Future Domain Risk Rules | unknown |

## Playbook Image
---
![Recorded Future Domain Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/domain_reputation.png)