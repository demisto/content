File Enrichment using Recorded Future Intelligence

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

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
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| File.SHA256 | File SHA\-256 | unknown |
| File.SHA512 | File SHA\-512 | unknown |
| File.SHA1 | File SHA\-1 | unknown |
| File.MD5 | File MD5 | unknown |
| File.CRC32 | File CRC32 | unknown |
| File.CTPH | File CTPH | unknown |
| RecordedFuture.File.criticality | Risk Criticality | unknown |
| RecordedFuture.File.criticalityLabel | Risk Criticality Label | unknown |
| RecordedFuture.File.riskString | Risk String | unknown |
| RecordedFuture.File.riskSummary | Risk Summary | unknown |
| RecordedFuture.File.rules | Risk Rules | unknown |
| RecordedFuture.File.score | Risk Score | unknown |
| RecordedFuture.File.firstSeen | Evidence First Seen | unknown |
| RecordedFuture.File.lastSeen | Evidence Last Seen | unknown |
| RecordedFuture.File.intelCard | Recorded Future Intelligence Card URL | unknown |
| RecordedFuture.File.hashAlgorithm | Hash Algorithm | unknown |
| RecordedFuture.File.type | Entity Type | unknown |
| RecordedFuture.File.name | Entity | unknown |
| RecordedFuture.File.id | Recorded Future Entity ID | unknown |
| RecordedFuture.File.metrics.type | Recorded Future Metrics Type | unknown |
| RecordedFuture.File.metrics.value | Recorded Future Metrics Value | unknown |
| RecordedFuture.File.threatLists.description | Recorded Future Threat List Description | unknown |
| RecordedFuture.File.threatLists.id | Recorded Future Threat List ID | unknown |
| RecordedFuture.File.threatLists.name | Recorded Future Threat List Name | unknown |
| RecordedFuture.File.threatLists.type | Recorded Future Threat List Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedAttacker.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedAttacker.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedAttacker.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedAttacker.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedTarget.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedTarget.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedTarget.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedTarget.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedMalware.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedMalware.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedMalware.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedMalware.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedProduct.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedProduct.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedProduct.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedProduct.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedCountries.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedCountries.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedCountries.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedCountries.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedHash.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedHash.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedHash.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedHash.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedTechnology.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedTechnology.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedTechnology.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedTechnology.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedOperations.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedOperations.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedOperations.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedOperations.type | Recorded Future Related Type | unknown |
| RecordedFuture.File.relatedEntities.RelatedCompany.count | Recorded Future Related Count | unknown |
| RecordedFuture.File.relatedEntities.RelatedCompany.id | Recorded Future Related ID | unknown |
| RecordedFuture.File.relatedEntities.RelatedCompany.name | Recorded Future Related Name | unknown |
| RecordedFuture.File.relatedEntities.RelatedCompany.type | Recorded Future Related Type | unknown |

## Playbook Image
---
![Recorded Future File Intelligence](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/file_enrich.png)