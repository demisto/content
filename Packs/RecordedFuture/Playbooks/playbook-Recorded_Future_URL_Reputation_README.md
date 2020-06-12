URL reputation using Recorded Future SOAR Enrichment

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

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
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| URL.Malicious.Vendor | For malicious URLs, the vendor that made the decision | unknown |
| URL.Malicious.Description | For malicious URLs, the reason that the vendor made the decision | unknown |
| URL.Data | URL name | unknown |
| RecordedFuture.URL.riskScore | Recorded Future URL Risk Score | unknown |
| RecordedFuture.URL.riskLevel | Recorded Future URL Risk Level | unknown |
| RecordedFuture.URL.Evidence.rule | Recorded Risk Rule Name | unknown |
| RecordedFuture.URL.Evidence.mitigation | Recorded Risk Rule Mitigation | unknown |
| RecordedFuture.URL.Evidence.description | Recorded Risk Rule description | unknown |
| RecordedFuture.URL.Evidence.timestamp | Recorded Risk Rule timestamp | unknown |
| RecordedFuture.URL.Evidence.level | Recorded Risk Rule Level | unknown |
| RecordedFuture.URL.Evidence.ruleid | Recorded Risk Rule ID | unknown |
| RecordedFuture.URL.name | URL | unknown |
| RecordedFuture.URL.maxRules | Maximum count of Recorded Future URL Risk Rules | unknown |
| RecordedFuture.URL.ruleCount | Number of triggered Recorded Future URL Risk Rules | unknown |

## Playbook Image
---
![Recorded Future URL Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/url_reputation.png)