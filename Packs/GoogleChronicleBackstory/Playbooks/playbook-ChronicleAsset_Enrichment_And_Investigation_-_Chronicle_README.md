This playbook receives indicators from its parent playbook, performs enrichment and investigation for each one of them, provides an opportunity to isolate and block the Hostname or IP Address associated with the current indicator, and gives out a list of isolated and blocked entities. This playbook also lists out the events fetched for the asset identifier information associated with the indicator.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* List Device Events - Chronicle
* ChronicleAsset Hostname And IP Address Enrichment And Investigation - Chronicle

### Integrations
This playbook does not use any integrations.

### Scripts
* SixgillSearchIndicators
* DeleteContext

### Commands
* setIndicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| chronicleasset_value | The value of the ChronicleAsset indicator. |  | Required |
| chronicleasset_support_contact | The support email address for the chronicle asset. | incident.chronicleassetsupportcontact | Optional |
| auto_block_entities | Autoblock the detected suspicious IP Address\(es\). You can set this as 'Yes' or 'No' manually here or you can set it into a custom incident field 'Chronicle Auto Block Entities'. | incident.chronicleautoblockentities | Optional |
| skip_entity_isolation | Skip the isolation of entities. You can set this as 'Yes' or 'No' manually here or you can set it into a custom incident field 'Chronicle Skip Entity Isolation'. | incident.chronicleskipentityisolation | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IsolatedEntities | List of the isolated entities. | unknown |
| PotentiallyBlockedIPs | List of potentially blocked IP Addresses. | unknown |

## Playbook Image
---
![ChronicleAsset Enrichment And Investigation - Chronicle](../doc_files/ChronicleAsset_Enrichment_And_Investigation_-_Chronicle.png)