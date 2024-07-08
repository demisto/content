URL Enrichment using Recorded Future Intelligence

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
| URL | The URL to enrich. | URL.Data | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Type | Indicator type | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |
| URL.Data | URL | string |
| RecordedFuture.URL.criticality | Risk Criticality | number |
| RecordedFuture.URL.criticalityLabel | Risk Criticality Label | string |
| RecordedFuture.URL.riskString | Risk String | string |
| RecordedFuture.URL.riskSummary | Risk Summary | string |
| RecordedFuture.URL.rules | Risk Rules | string |
| RecordedFuture.URL.score | Risk Score | number |
| RecordedFuture.URL.firstSeen | Evidence First Seen | date |
| RecordedFuture.URL.lastSeen | Evidence Last Seen | date |
| RecordedFuture.URL.intelCard | Recorded Future Intelligence Card URL | string |
| RecordedFuture.URL.type | Entity Type | string |
| RecordedFuture.URL.name | Entity | string |
| RecordedFuture.URL.id | Recorded Future Entity ID | string |
| RecordedFuture.URL.metrics.type | Recorded Future Metrics Type | string |
| RecordedFuture.URL.metrics.value | Recorded Future Metrics Value | number |
| RecordedFuture.URL.threatLists.description | Recorded Future Threat List Description | string |
| RecordedFuture.URL.threatLists.id | Recorded Future Threat List ID | string |
| RecordedFuture.URL.threatLists.name | Recorded Future Threat List Name | string |
| RecordedFuture.URL.threatLists.type | Recorded Future Threat List Type | string |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedTarget.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedTarget.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedTarget.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedTarget.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedMalware.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedMalware.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedMalware.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedMalware.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedProduct.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedProduct.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedProduct.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedProduct.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedCountries.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedCountries.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedCountries.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedCountries.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedHash.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedHash.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedHash.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedHash.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedOperations.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedOperations.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedOperations.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedOperations.type | Recorded Future Related Type | string |
| RecordedFuture.URL.relatedEntities.RelatedCompany.count | Recorded Future Related Count | number |
| RecordedFuture.URL.relatedEntities.RelatedCompany.id | Recorded Future Related ID | string |
| RecordedFuture.URL.relatedEntities.RelatedCompany.name | Recorded Future Related Name | string |
| RecordedFuture.URL.relatedEntities.RelatedCompany.type | Recorded Future Related Type | string |

## Playbook Image
---
![Recorded Future URL Intelligence](../doc_files/url_enrich.png)
