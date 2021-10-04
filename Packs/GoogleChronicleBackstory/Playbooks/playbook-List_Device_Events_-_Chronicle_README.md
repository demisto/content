This playbook receives ChronicleAsset identifier information and provides a list of events related to each one of them.
Supported integration: Chronicle

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
**Chronicle**

### Scripts
**DeleteContext**

### Commands
***gcb-list-events***

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| chronicleasset_hostname | The hostname associated with the ChronicleAsset. |  | Optional |
| chronicleasset_ip | The IP address associated with the ChronicleAsset. |  | Optional |
| chronicleasset_mac | The MAC address associated with the ChronicleAsset. |  | Optional |
| chronicleasset_product_id | The product ID associated with the ChronicleAsset. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GoogleChronicleBackstory.Events | List of events associated with the ChronicleAsset. | unknown |

## Playbook Image
---
![List Device Events - Chronicle](https://raw.githubusercontent.com/demisto/content/94f5c6cd2d456d700e20cc18c233cad547c04d63/Packs/GoogleChronicleBackstory/doc_files/List_Device_Events_-_Chronicle.png)
