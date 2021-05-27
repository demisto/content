Entity Reputation using sub-playbooks

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts. Depends on the recorded futures indicator field; risk rules.

### Sub-playbooks
* Recorded Future Domain Reputation
* Recorded Future URL Reputation
* Recorded Future CVE Reputation
* Recorded Future IP Reputation
* Recorded Future File Reputation

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
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Type | Indicator type | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |
| CVE.ID | Vulnerability name | string |
| Domain.Name | Domain name | string |
| Domain.Malicious.Vendor | For malicious Domains, the vendor that made the decision | string |
| Domain.Malicious.Description | For malicious Domains, the reason that the vendor made the decision | string |
| IP.Address | IP address | string |
| IP.Malicious.Vendor | For malicious IP addresses, the vendor that made the decision | string |
| IP.Malicious.Description | For malicious IP addresses, the reason that the vendor made the decision | string |
| URL.Data | URL name | string |
| URL.Malicious.Vendor | For malicious URLs, the vendor that made the decision | string |
| URL.Malicious.Description | For malicious URLs, the reason that the vendor made the decision | string |
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
| RecordedFuture.IP.riskScore | Recorded Future IP Risk Score | number |
| RecordedFuture.IP.riskLevel | Recorded Future IP Risk Level | string |
| RecordedFuture.IP.Evidence.rule | Recorded Risk Rule Name | string |
| RecordedFuture.IP.Evidence.mitigation | Recorded Risk Rule Mitigation | string |
| RecordedFuture.IP.Evidence.description | Recorded Risk Rule Description | string |
| RecordedFuture.IP.Evidence.timestamp | Recorded Risk Rule Timestamp | date |
| RecordedFuture.IP.Evidence.level | Recorded Risk Rule Level | number |
| RecordedFuture.IP.Evidence.ruleid | Recorded Risk Rule ID | string |
| RecordedFuture.IP.name | IP Address | string |
| RecordedFuture.IP.maxRules | Maximum count of Recorded Future IP Risk Rules | number |
| RecordedFuture.IP.ruleCount | Number of triggered Recorded Future IP Risk Rules | number |
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
![Recorded Future IOC Reputation](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/ioc_reputation.png)
