Domain reputation using Recorded Future SOAR Enrichment

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts. Depends on the recorded futures indicator field; risk rules.

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
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Type | Indicator type | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |
| Domain.Malicious.Vendor | For malicious Domains, the vendor that made the decision | string |
| Domain.Malicious.Description | For malicious Domains, the reason that the vendor made the decision | string |
| Domain.Name | Domain name | string |
| RecordedFuture.Domain.riskScore | Recorded Future Domain Risk Score | number |
| RecordedFuture.Domain.riskLevel | Recorded Future Domain Risk Level | string |
| RecordedFuture.Domain.Evidence.rule | Recorded Risk Rule Name | string |
| RecordedFuture.Domain.Evidence.mitigation | Recorded Risk Rule Mitigation | string |
| RecordedFuture.Domain.Evidence.description | Recorded Risk Rule description | string |
| RecordedFuture.Domain.Evidence.timestamp | Recorded Risk Rule timestamp | date |
| RecordedFuture.Domain.Evidence.level | Recorded Risk Rule Level | number |
| RecordedFuture.Domain.Evidence.ruleid | Recorded Risk Rule ID | string |
| RecordedFuture.Domain.name | Domain name | string |
| RecordedFuture.Domain.maxRules | Maximum count of Recorded Future Domain Risk Rules | number |
| RecordedFuture.Domain.ruleCount | Number of triggered Recorded Future Domain Risk Rules | number |

## Playbook Image
---
![Recorded Future Domain Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/domain_reputation.png)
