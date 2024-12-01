Domain Enrichment using Recorded Future Intelligence

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
| Domain | The domain name to enrich. | Domain.Name | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Type | Indicator type | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |
| Domain.Name | Domain name | string |
| RecordedFuture.Domain.criticality | Risk Criticality | number |
| RecordedFuture.Domain.criticalityLabel | Risk Criticality Label | string |
| RecordedFuture.Domain.riskString | Risk String | string |
| RecordedFuture.Domain.riskSummary | Risk Summary | string |
| RecordedFuture.Domain.rules | Risk Rules | string |
| RecordedFuture.Domain.score | Risk Score | number |
| RecordedFuture.Domain.firstSeen | Evidence First Seen | date |
| RecordedFuture.Domain.lastSeen | Evidence Last Seen | date |
| RecordedFuture.Domain.intelCard | Recorded Future Intelligence Card URL | string |
| RecordedFuture.Domain.type | Entity Type | string |
| RecordedFuture.Domain.name | Entity | string |
| RecordedFuture.Domain.id | Recorded Future Entity ID | string |
| RecordedFuture.Domain.metrics.type | Recorded Future Metrics Type | string |
| RecordedFuture.Domain.metrics.value | Recorded Future Metrics Value | number |
| RecordedFuture.Domain.threatLists.description | Recorded Future Threat List Description | string |
| RecordedFuture.Domain.threatLists.id | Recorded Future Threat List ID | string |
| RecordedFuture.Domain.threatLists.name | Recorded Future Threat List Name | string |
| RecordedFuture.Domain.threatLists.type | Recorded Future Threat List Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedHash.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedHash.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedHash.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedHash.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.type | Recorded Future Related Type | string |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.count | Recorded Future Related Count | number |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.id | Recorded Future Related ID | string |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.name | Recorded Future Related Name | string |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.type | Recorded Future Related Type | string |

## Playbook Image
---
![Recorded Future Domain Intelligence](../doc_files/domain_enrich.png)
