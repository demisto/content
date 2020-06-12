URL Enrichment using Recorded Future Intelligence

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
| URL | The URL to enrich. | URL.Data | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| URL.Data | URL | unknown |
| RecordedFuture.URL.criticality | Risk Criticality | unknown |
| RecordedFuture.URL.criticalityLabel | Risk Criticality Label | unknown |
| RecordedFuture.URL.riskString | Risk String | unknown |
| RecordedFuture.URL.riskSummary | Risk Summary | unknown |
| RecordedFuture.URL.rules | Risk Rules | unknown |
| RecordedFuture.URL.score | Risk Score | unknown |
| RecordedFuture.URL.firstSeen | Evidence First Seen | unknown |
| RecordedFuture.URL.lastSeen | Evidence Last Seen | unknown |
| RecordedFuture.URL.intelCard | Recorded Future Intelligence Card URL | unknown |
| RecordedFuture.URL.type | Entity Type | unknown |
| RecordedFuture.URL.name | Entity | unknown |
| RecordedFuture.URL.id | Recorded Future Entity ID | unknown |
| RecordedFuture.URL.metrics.type | Recorded Future Metrics Type | unknown |
| RecordedFuture.URL.metrics.value | Recorded Future Metrics Value | unknown |
| RecordedFuture.URL.threatLists.description | Recorded Future Threat List Description | unknown |
| RecordedFuture.URL.threatLists.id | Recorded Future Threat List ID | unknown |
| RecordedFuture.URL.threatLists.name | Recorded Future Threat List Name | unknown |
| RecordedFuture.URL.threatLists.type | Recorded Future Threat List Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedTarget.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedTarget.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedTarget.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedTarget.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedMalware.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedMalware.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedMalware.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedMalware.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedProduct.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedProduct.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedProduct.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedProduct.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCountries.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCountries.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCountries.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCountries.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedHash.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedHash.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedHash.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedHash.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedOperations.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedOperations.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedOperations.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedOperations.type | Recorded Future Related Type | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCompany.count | Recorded Future Related Count | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCompany.id | Recorded Future Related ID | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCompany.name | Recorded Future Related Name | unknown |
| RecordedFuture.URL.relatedEntities.RelatedCompany.type | Recorded Future Related Type | unknown |

## Playbook Image
---
![Recorded Future URL Intelligence](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/url_enrich.png)