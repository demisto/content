File Enrichment using Recorded Future Intelligence

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts. Depends on the recorded futures indicator field; risk rules.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Recorded Future v2

### Scripts
This playbook does not use any scripts.

### Commands
* recordedfuture-intelligence

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | File MD5 hash to enrich. | File.MD5 | Optional |
| SHA256 | File SHA\-256 hash to enrich. | File.SHA256 | Optional |
| SHA1 | File SHA\-1 hash to enrich. | File.SHA1 | Optional |

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
| RecordedFuture.File.criticality | Risk Criticality | number |
| RecordedFuture.File.criticalityLabel | Risk Criticality Label | string |
| RecordedFuture.File.riskString | Risk String | string |
| RecordedFuture.File.riskSummary | Risk Summary | string |
| RecordedFuture.File.rules | Risk Rules | string |
| RecordedFuture.File.score | Risk Score | number |
| RecordedFuture.File.firstSeen | Evidence First Seen | date |
| RecordedFuture.File.lastSeen | Evidence Last Seen | date |
| RecordedFuture.File.intelCard | Recorded Future Intelligence Card URL | string |
| RecordedFuture.File.hashAlgorithm | Hash Algorithm | string |
| RecordedFuture.File.type | Entity Type | string |
| RecordedFuture.File.name | Entity | string |
| RecordedFuture.File.id | Recorded Future Entity ID | string |
| RecordedFuture.File.metrics.type | Recorded Future Metrics Type | string |
| RecordedFuture.File.metrics.value | Recorded Future Metrics Value | number |
| RecordedFuture.File.threatLists.description | Recorded Future Threat List Description | string |
| RecordedFuture.File.threatLists.id | Recorded Future Threat List ID | string |
| RecordedFuture.File.threatLists.name | Recorded Future Threat List Name | string |
| RecordedFuture.File.threatLists.type | Recorded Future Threat List Type | string |
| RecordedFuture.File.relatedEntities.RelatedAttacker.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedAttacker.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedAttacker.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedAttacker.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedTarget.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedTarget.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedTarget.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedTarget.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedMalware.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedMalware.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedMalware.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedMalware.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedProduct.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedProduct.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedProduct.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedProduct.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedCountries.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedCountries.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedCountries.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedCountries.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedHash.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedHash.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedHash.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedHash.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedTechnology.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedTechnology.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedTechnology.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedTechnology.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedOperations.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedOperations.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedOperations.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedOperations.type | Recorded Future Related Type | string |
| RecordedFuture.File.relatedEntities.RelatedCompany.count | Recorded Future Related Count | number |
| RecordedFuture.File.relatedEntities.RelatedCompany.id | Recorded Future Related ID | string |
| RecordedFuture.File.relatedEntities.RelatedCompany.name | Recorded Future Related Name | string |
| RecordedFuture.File.relatedEntities.RelatedCompany.type | Recorded Future Related Type | string |

## Playbook Image
---
![Recorded Future File Intelligence](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/cve_enrich.png)
