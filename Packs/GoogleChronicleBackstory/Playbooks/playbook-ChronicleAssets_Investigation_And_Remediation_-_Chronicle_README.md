Performs enrichment and investigation of the ChronicleAsset type of indicators, provides an opportunity to remediate in case any of the ChronicleAsset information i.e. Hostname or IP Address is found to be malicious or suspicious, and sends out an email of the list of isolated and potentially blocked entities. To select the indicators you want to add, go to playbook inputs, choose "from indicators" and set your query. For example type:ChronicleAsset etc. The default playbook query is "type:ChronicleAsset". In case indicators with different query parameters are to be investigated, the query must be edited accordingly. This playbook needs to be used with caution as it might use up the integration’s API license when running for large amounts of indicators.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* ChronicleAsset Investigation - Chronicle

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input | type:ChronicleAsset | Optional |
| chronicleasset_support_contact | The support email address for the chronicle asset. | incident.chronicleassetsupportcontact | Optional |
| auto_block_entities | Autoblock the detected suspicious IP Address\(es\). You can set this as 'Yes' or 'No' manually here or you can set it into a custom incident field 'Chronicle Auto Block Entities'. | incident.chronicleautoblockentities | Optional |
| skip_entity_isolation | Skip the isolation of entities. You can set this as 'Yes' or 'No' manually here or you can set it into a custom incident field 'Chronicle Skip Entity Isolation'. | incident.chronicleskipentityisolation | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![ChronicleAssets Investigation And Remediation - Chronicle](https://raw.githubusercontent.com/demisto/content/94f5c6cd2d456d700e20cc18c233cad547c04d63/Packs/GoogleChronicleBackstory/doc_files/ChronicleAssets_Investigation_And_Remediation_-_Chronicle.png)