IP address reputation using Recorded Future SOAR Enrichment

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Recorded Future v2

### Scripts
This playbook does not use any scripts.

### Commands
* ip

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | The IP address to get reputation of. | IP.Address | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| IP.Malicious.Vendor | For malicious IP addresses, the vendor that made the decision | unknown |
| IP.Malicious.Description | For malicious IP addresses, the reason that the vendor made the decision | unknown |
| IP.Address | IP address | unknown |
| RecordedFuture.IP.riskScore | Recorded Future IP Risk Score | unknown |
| RecordedFuture.IP.riskLevel | Recorded Future IP Risk Level | unknown |
| RecordedFuture.IP.Evidence.rule | Recorded Risk Rule Name | unknown |
| RecordedFuture.IP.Evidence.mitigation | Recorded Risk Rule Mitigation | unknown |
| RecordedFuture.IP.Evidence.description | Recorded Risk Rule Description | unknown |
| RecordedFuture.IP.Evidence.timestamp | Recorded Risk Rule Timestamp | unknown |
| RecordedFuture.IP.Evidence.level | Recorded Risk Rule Level | unknown |
| RecordedFuture.IP.Evidence.ruleid | Recorded Risk Rule ID | unknown |
| RecordedFuture.IP.name | IP Address | unknown |
| RecordedFuture.IP.maxRules | Maximum count of Recorded Future IP Risk Rules | unknown |
| RecordedFuture.IP.ruleCount | Number of triggered Recorded Future IP Risk Rules | unknown |

## Playbook Image
---
![Recorded Future IP Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/ip_reputation.png)