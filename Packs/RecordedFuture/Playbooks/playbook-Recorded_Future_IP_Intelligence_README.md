IP Address Enrichment using Recorded Future Intelligence

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
| IP | The IP address to enrich. | IP.Address | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Type | Indicator type | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |
| IP.Address | IP address | string |
| IP.ASN | ASN | string |
| IP.Geo.Country | IP Geolocation Country | string |
| RecordedFuture.IP.criticality | Risk Criticality | number |
| RecordedFuture.IP.criticalityLabel | Risk Criticality Label | string |
| RecordedFuture.IP.riskString | Risk String | string |
| RecordedFuture.IP.riskSummary | Risk Summary | string |
| RecordedFuture.IP.rules | Risk Rules | string |
| RecordedFuture.IP.score | Risk Score | number |
| RecordedFuture.IP.firstSeen | Evidence First Seen | date |
| RecordedFuture.IP.lastSeen | Evidence Last Seen | date |
| RecordedFuture.IP.intelCard | Recorded Future Intelligence Card URL | string |
| RecordedFuture.IP.type | Entity Type | string |
| RecordedFuture.IP.name | Entity | string |
| RecordedFuture.IP.id | Recorded Future Entity ID | string |
| RecordedFuture.IP.location.asn | ASN number | string |
| RecordedFuture.IP.location.cidr.id | Recorded Future CIDR ID | string |
| RecordedFuture.IP.location.cidr.name | CIDR | string |
| RecordedFuture.IP.location.cidr.type | CIDR Type | string |
| RecordedFuture.IP.location.location.city | IP Geolocation City | string |
| RecordedFuture.IP.location.location.continent | IP Geolocation Continent | string |
| RecordedFuture.IP.location.location.country | IP Geolocation Country | string |
| RecordedFuture.IP.location.organization | IP Geolocation Organization | string |
| RecordedFuture.IP.metrics.type | Recorded Future Metrics Type | string |
| RecordedFuture.IP.metrics.value | Recorded Future Metrics Value | number |
| RecordedFuture.IP.threatLists.description | Recorded Future Threat List Description | string |
| RecordedFuture.IP.threatLists.id | Recorded Future Threat List ID | string |
| RecordedFuture.IP.threatLists.name | Recorded Future Threat List Name | string |
| RecordedFuture.IP.threatLists.type | Recorded Future Threat List Type | string |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedTarget.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedTarget.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedTarget.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedTarget.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedMalware.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedMalware.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedMalware.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedMalware.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedProduct.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedProduct.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedProduct.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedProduct.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedCountries.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedCountries.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedCountries.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedCountries.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedHash.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedHash.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedHash.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedHash.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedOperations.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedOperations.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedOperations.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedOperations.type | Recorded Future Related Type | string |
| RecordedFuture.IP.relatedEntities.RelatedCompany.count | Recorded Future Related Count | number |
| RecordedFuture.IP.relatedEntities.RelatedCompany.id | Recorded Future Related ID | string |
| RecordedFuture.IP.relatedEntities.RelatedCompany.name | Recorded Future Related Name | string |
| RecordedFuture.IP.relatedEntities.RelatedCompany.type | Recorded Future Related Type | string |

## Playbook Image
---
![Recorded Future IP Intelligence](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/ip_enrich.png)
