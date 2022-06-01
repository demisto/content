This playbook receives indicators from its parent playbook, performs enrichment and investigation for each one of them, provides an opportunity to isolate and block the hostname or IP address associated with the current indicator, and gives out a list of isolated and blocked entities. This playbook also lists the events fetched for the asset identifier information associated with the indicator.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
**List Device Events - Chronicle**
**Hostname And IP Address Investigation And Remediation - Chronicle**

### Integrations
This playbook does not use any integrations.

### Scripts
- **SixgillSearchIndicators**
- **DeleteContext**

### Commands
***setIndicator***

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| chronicleasset_value | The value of the ChronicleAsset indicator. |  | Required |
| chronicleasset_support_contact | The support email address for the chronicle asset. | incident.chronicleassetsupportcontact | Optional |
| auto_block_entities | Autoblock the detected suspicious IP Address\(es\). You can manually set this as 'Yes' or 'No' here or you can set it into a 'Chronicle Auto Block Entities' custom incident field. | incident.chronicleautoblockentities | Optional |
| skip_entity_isolation | Skip the isolation of entities. You can manually set this as 'Yes' or 'No' here or you can set it into a 'Chronicle Skip Entity Isolation' custom incident field. | incident.chronicleskipentityisolation | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IsolatedEntities | List of the isolated entities. | unknown |
| PotentiallyBlockedIPs | List of potentially blocked IP addresses. | unknown |

## Playbook Image
---
![ChronicleAsset Investigation - Chronicle](https://raw.githubusercontent.com/demisto/content/16ffc1758735f7ac94990651419a94961c81f329/Packs/GoogleChronicleBackstory/doc_files/ChronicleAsset_Investigation_-_Chronicle.png)
