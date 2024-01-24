This is a *sub-playbook* of "Cortex XDR IOCs - Push new IOCs to XDR (Main)". This playbook disables indicators in Cortex XDR after they expire from Cortex XSOAR using a loop and querying on the "xdr_pushed" tag.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Cortex XDR - IOC

### Scripts

* Set
* GetIndicatorsByQuery
* DeleteContext
* ReadFile

### Commands

* appendIndicatorField
* xdr-iocs-disable

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| batch_size | This parameter will set the batch size to be pushed into Cortex XDR with every iteration of the loop. | 4000 | Optional |
| query | The query used to search for IOCs from Cortex XSOAR to be pushed into Cortex XDR. This query must include \`-tags:xdr_pushed and -tags:xdr_not_processed\` in order to work properly. | reputation:Bad and (type:File or type:Domain or type:IP) and expirationStatus:active and -tags:xdr_pushed and -tags:xdr_not_processed | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex XDR IOCs - Disable expired IOCs in XDR](../doc_files/Cortex_XDR_IOCs_-_Disable_expired_IOCs_in_XDR.png)
