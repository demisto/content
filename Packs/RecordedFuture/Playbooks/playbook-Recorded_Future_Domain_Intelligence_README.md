Domain Enrichment using Recorded Future Intelligence

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
| Domain | The domain name to enrich. | Domain.Name | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| Domain.Name | Domain name | unknown |
| RecordedFuture.Domain.criticality | Risk Criticality | unknown |
| RecordedFuture.Domain.criticalityLabel | Risk Criticality Label | unknown |
| RecordedFuture.Domain.riskString | Risk String | unknown |
| RecordedFuture.Domain.riskSummary | Risk Summary | unknown |
| RecordedFuture.Domain.rules | Risk Rules | unknown |
| RecordedFuture.Domain.score | Risk Score | unknown |
| RecordedFuture.Domain.firstSeen | Evidence First Seen | unknown |
| RecordedFuture.Domain.lastSeen | Evidence Last Seen | unknown |
| RecordedFuture.Domain.intelCard | Recorded Future Intelligence Card URL | unknown |
| RecordedFuture.Domain.hashAlgorithm | Hash Algorithm | unknown |
| RecordedFuture.Domain.type | Entity Type | unknown |
| RecordedFuture.Domain.name | Entity | unknown |
| RecordedFuture.Domain.id | Recorded Future Entity ID | unknown |
| RecordedFuture.Domain.location.asn | ASN number | unknown |
| RecordedFuture.Domain.location.cidr.id | Recorded Future CIDR ID | unknown |
| RecordedFuture.Domain.location.cidr.name | CIDR | unknown |
| RecordedFuture.Domain.location.cidr.type | CIDR Type | unknown |
| RecordedFuture.Domain.location.location.city | IP Geolocation City | unknown |
| RecordedFuture.Domain.location.location.continent | IP Geolocation Continent | unknown |
| RecordedFuture.Domain.location.location.country | IP Geolocation Country | unknown |
| RecordedFuture.Domain.location.organization | IP Geolocation Organization | unknown |
| RecordedFuture.Domain.metrics.type | Recorded Future Metrics Type | unknown |
| RecordedFuture.Domain.metrics.value | Recorded Future Metrics Value | unknown |
| RecordedFuture.Domain.threatLists.description | Recorded Future Threat List Description | unknown |
| RecordedFuture.Domain.threatLists.id | Recorded Future Threat List ID | unknown |
| RecordedFuture.Domain.threatLists.name | Recorded Future Threat List Name | unknown |
| RecordedFuture.Domain.threatLists.type | Recorded Future Threat List Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedHash.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedHash.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedHash.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedHash.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.type | Recorded Future Related Type | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.count | Recorded Future Related Count | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.id | Recorded Future Related ID | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.name | Recorded Future Related Name | unknown |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.type | Recorded Future Related Type | unknown |

## Playbook Image
---
![Recorded Future Domain Intelligence](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/domain_enrich.png)