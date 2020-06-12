CVE Enrichment using Recorded Future Intelligence

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
| CVE | The CVE ID to enrich. | CVE.ID | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| CVE.ID | Vulnerability name | unknown |
| RecordedFuture.CVE.criticality | Risk Criticality | unknown |
| RecordedFuture.CVE.criticalityLabel | Risk Criticality Label | unknown |
| RecordedFuture.CVE.riskString | Risk String | unknown |
| RecordedFuture.CVE.riskSummary | Risk Summary | unknown |
| RecordedFuture.CVE.rules | Risk Rules | unknown |
| RecordedFuture.CVE.score | Risk Score | unknown |
| RecordedFuture.CVE.firstSeen | Evidence First Seen | unknown |
| RecordedFuture.CVE.lastSeen | Evidence Last Seen | unknown |
| RecordedFuture.CVE.intelCard | Recorded Future Intelligence Card URL | unknown |
| RecordedFuture.CVE.type | Entity Type | unknown |
| RecordedFuture.CVE.name | Entity | unknown |
| RecordedFuture.CVE.id | Recorded Future Entity ID | unknown |
| RecordedFuture.CVE.metrics.type | Recorded Future Metrics Type | unknown |
| RecordedFuture.CVE.metrics.value | Recorded Future Metrics Value | unknown |
| RecordedFuture.CVE.threatLists.description | Recorded Future Threat List Description | unknown |
| RecordedFuture.CVE.threatLists.id | Recorded Future Threat List ID | unknown |
| RecordedFuture.CVE.threatLists.name | Recorded Future Threat List Name | unknown |
| RecordedFuture.CVE.threatLists.type | Recorded Future Threat List Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedTarget.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedTarget.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedTarget.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedTarget.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedMalware.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedMalware.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedMalware.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedMalware.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedProduct.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedProduct.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedProduct.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedProduct.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCountries.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCountries.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCountries.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCountries.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedHash.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedHash.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedHash.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedHash.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedOperations.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedOperations.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedOperations.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedOperations.type | Recorded Future Related Type | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCompany.count | Recorded Future Related Count | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCompany.id | Recorded Future Related ID | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCompany.name | Recorded Future Related Name | unknown |
| RecordedFuture.CVE.relatedEntities.RelatedCompany.type | Recorded Future Related Type | unknown |

## Playbook Image
---
![Recorded Future CVE Intelligence](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/cve_enrich.png)