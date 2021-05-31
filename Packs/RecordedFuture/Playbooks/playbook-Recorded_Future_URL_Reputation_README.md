URL reputation using Recorded Future SOAR Enrichment

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts. Depends on the recorded futures indicator field; risk rules.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Recorded Future v2

### Scripts
This playbook does not use any scripts.

### Commands
* url

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | URL to get reputation of. | URL.Data | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Type | Indicator type | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |
| URL.Malicious.Vendor | For malicious URLs, the vendor that made the decision | string |
| URL.Malicious.Description | For malicious URLs, the reason that the vendor made the decision | string |
| URL.Data | URL name | string |
| RecordedFuture.URL.riskScore | Recorded Future URL Risk Score | number |
| RecordedFuture.URL.riskLevel | Recorded Future URL Risk Level | string |
| RecordedFuture.URL.Evidence.rule | Recorded Risk Rule Name | string |
| RecordedFuture.URL.Evidence.mitigation | Recorded Risk Rule Mitigation | string |
| RecordedFuture.URL.Evidence.description | Recorded Risk Rule description | string |
| RecordedFuture.URL.Evidence.timestamp | Recorded Risk Rule timestamp | date |
| RecordedFuture.URL.Evidence.level | Recorded Risk Rule Level | number |
| RecordedFuture.URL.Evidence.ruleid | Recorded Risk Rule ID | string |
| RecordedFuture.URL.name | URL | string |
| RecordedFuture.URL.maxRules | Maximum count of Recorded Future URL Risk Rules | number |
| RecordedFuture.URL.ruleCount | Number of triggered Recorded Future URL Risk Rules | number |

## Playbook Image
---
![Recorded Future URL Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/url_reputation.png)
