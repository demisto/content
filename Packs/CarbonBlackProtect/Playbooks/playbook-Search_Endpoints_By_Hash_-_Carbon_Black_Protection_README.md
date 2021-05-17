Hunts for endpoint activity involving hash IOCs, using Carbon Black Protection.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* carbonblackprotection

### Scripts
* CBPCatalogFindHash
* Exists
* CBPFindRule
* Set

### Commands
* cbp-computer-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Hash | The MD5 file Hash to hunt for. | MD5 | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.Hostname | The device hostname. | string |
| Endpoint | The endpoint. | unknown |

## Playbook Image
---
![Search_Endpoints_By_Hash_Carbon_Black_Protection](https://raw.githubusercontent.com/demisto/content/f975de39b05cd3560b782f54d37637741d87ff65/docs/images/playbooks/Search_Endpoints_By_Hash_Carbon_Black_Protection.png)
