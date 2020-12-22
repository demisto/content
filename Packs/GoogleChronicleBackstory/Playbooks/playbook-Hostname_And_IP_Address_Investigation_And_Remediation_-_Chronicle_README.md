This playbook receives the ChronicleAsset type of indicators from its parent playbook "ChronicleAsset Investigation - Chronicle", performs enrichment and investigation for each one of them, provides an opportunity to isolate and block the hostname or IP address associated with the current indicator, and provides a list of isolated and blocked entities.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
- **Endpoint Enrichment - Generic v2.1**
- **IP Enrichment - Generic v2**
- **Isolate Endpoint - Generic**
- **Block IP - Generic v2**

### Integrations
This playbook does not use any integrations.

### Scripts
- **Set**
- **DeleteContext**

### Commands
- ***ip***
- ***setIndicator***
- ***df-get-asset***

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| chronicleasset_value | The value of the ChronicleAsset indicator. |  | Required |
| chronicleasset_hostname | The hostname associated with the ChronicleAsset. |  | Optional |
| chronicleasset_ip | The IP address associated with the ChronicleAsset. |  | Optional |
| chronicleasset_support_contact | The support email address for the ChronicleAsset. | incident.chronicleassetsupportcontact | Optional |
| auto_block_entities | Autoblock the detected suspicious IP address\(es\). You can manually set this as 'Yes' or 'No' here or you can set it in a 'Chronicle Auto Block Entities' custom incident field. | incident.chronicleautoblockentities | Optional |
| skip_entity_isolation | Skip the isolation of entities. You can manually set this as 'Yes' or 'No' here or you can set it in a 'Chronicle Skip Entity Isolation' custom incident field. | incident.chronicleskipentityisolation | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IsolatedEntities | List of the isolated entities. | unknown |
| PotentiallyBlockedIPs | List of potentially blocked IP addresses. | unknown |

## Playbook Image
---
![Hostname And IP Address Investigation And Remediation - Chronicle](https://raw.githubusercontent.com/demisto/content/6ed8556fa886b498aaeec84580c751fbc759eec9/Packs/GoogleChronicleBackstory/doc_files/Hostname_And_IP_Address_Investigation_And_Remediation_-_Chronicle.png)
