This is a *sub-playbook* of "Cortex XDR IOCs - Push new IOCs to XDR - Main" and should not be run on its own. This sub-playbook will retrieve IOCs according to the users query input (passed from the main playbook) and push them into XDR, and mark them as "xdr_pushed" or "xdr_not_processed" for further processing.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

XDR_iocs

### Scripts

* ReadFile
* DeleteContext
* GetIndicatorsByQuery
* Set

### Commands

* appendIndicatorField
* xdr-iocs-push

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| batch_size |  |  | Optional |
| query |  |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex XDR IOCs - Push new IOCs to XDR](../doc_files/Cortex_XDR_IOCs_-_Push_new_IOCs_to_XDR.png)
