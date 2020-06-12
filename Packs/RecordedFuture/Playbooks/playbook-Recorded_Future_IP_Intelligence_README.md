IP Address Enrichment using Recorded Future Intelligence

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
| IP | The IP address to enrich. | IP.Address | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | unknown |
| DBotScore.Type | Indicator type | unknown |
| DBotScore.Vendor | Vendor used to calculate the score | unknown |
| DBotScore.Score | The actual score | unknown |
| IP.Address | IP address | unknown |
| IP.ASN | ASN | unknown |
| IP.Geo.Country | IP Geolocation Country | unknown |
| RecordedFuture.IP.criticality | Risk Criticality | unknown |
| RecordedFuture.IP.criticalityLabel | Risk Criticality Label | unknown |
| RecordedFuture.IP.riskString | Risk String | unknown |
| RecordedFuture.IP.riskSummary | Risk Summary | unknown |
| RecordedFuture.IP.rules | Risk Rules | unknown |
| RecordedFuture.IP.score | Risk Score | unknown |
| RecordedFuture.IP.firstSeen | Evidence First Seen | unknown |
| RecordedFuture.IP.lastSeen | Evidence Last Seen | unknown |
| RecordedFuture.IP.intelCard | Recorded Future Intelligence Card URL | unknown |
| RecordedFuture.IP.type | Entity Type | unknown |
| RecordedFuture.IP.name | Entity | unknown |
| RecordedFuture.IP.id | Recorded Future Entity ID | unknown |
| RecordedFuture.IP.location.asn | ASN number | unknown |
| RecordedFuture.IP.location.cidr.id | Recorded Future CIDR ID | unknown |
| RecordedFuture.IP.location.cidr.name | CIDR | unknown |
| RecordedFuture.IP.location.cidr.type | CIDR Type | unknown |
| RecordedFuture.IP.location.location.city | IP Geolocation City | unknown |
| RecordedFuture.IP.location.location.continent | IP Geolocation Continent | unknown |
| RecordedFuture.IP.location.location.country | IP Geolocation Country | unknown |
| RecordedFuture.IP.location.organization | IP Geolocation Organization | unknown |
| RecordedFuture.IP.metrics.type | Recorded Future Metrics Type | unknown |
| RecordedFuture.IP.metrics.value | Recorded Future Metrics Value | unknown |
| RecordedFuture.IP.threatLists.description | Recorded Future Threat List Description | unknown |
| RecordedFuture.IP.threatLists.id | Recorded Future Threat List ID | unknown |
| RecordedFuture.IP.threatLists.name | Recorded Future Threat List Name | unknown |
| RecordedFuture.IP.threatLists.type | Recorded Future Threat List Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedTarget.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedTarget.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedTarget.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedTarget.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedMalware.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedMalware.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedMalware.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedMalware.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedProduct.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedProduct.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedProduct.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedProduct.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCountries.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCountries.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCountries.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCountries.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedHash.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedHash.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedHash.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedHash.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedOperations.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedOperations.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedOperations.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedOperations.type | Recorded Future Related Type | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCompany.count | Recorded Future Related Count | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCompany.id | Recorded Future Related ID | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCompany.name | Recorded Future Related Name | unknown |
| RecordedFuture.IP.relatedEntities.RelatedCompany.type | Recorded Future Related Type | unknown |

## Playbook Image
---
![Recorded Future IP Intelligence](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/ip_enrich.png)