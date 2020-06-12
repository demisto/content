Entity Reputation using sub-playbooks

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Recorded Future CVE Reputation
* Recorded Future IP Reputation
* Recorded Future File Reputation
* Recorded Future URL Reputation
* Recorded Future Domain Reputation

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | The IP addresses to enrich | IP.Address | Optional |
| MD5 | File MD5 to enrich | File.MD5 | Optional |
| SHA256 | File SHA256 to enrich | File.SHA256 | Optional |
| SHA1 | File SHA1 to enrich | File.SHA1 | Optional |
| URL | URL to enrich | URL.Data | Optional |
| Domain | The domain name to enrich | Domain.Name | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| Domain.Name | Domain name | unknown |
| IP.Address | IP address | unknown |
| URL.Data | URL name | unknown |
| CVE.ID | CVE ID | unknown |
| File.SHA256 | File SHA\-256 | unknown |
| File.SHA512 | File SHA\-512 | unknown |
| File.SHA1 | File SHA\-1 | unknown |
| File.MD5 | File MD5 | unknown |
| File.CRC32 | File CRC32 | unknown |
| File.CTPH | File CTPH | unknown |
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
![Recorded Future IOC Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/ioc_reputation.png)