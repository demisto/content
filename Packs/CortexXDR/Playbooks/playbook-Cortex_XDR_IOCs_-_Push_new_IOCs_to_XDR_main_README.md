The playbook will "sync" IOCs into XDR by pushing new IOCs in and disabling expired IOCs.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* XDR IOCs - Push new IOCs to XDR (subplaybook)
* XDR IOCs - Disable expired IOCs in XDR (subplaybook)

### Integrations

This playbook does not use any integrations.

### Scripts

* Set

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| batch_size | The size of the batch of indicators to be pushed into XDR in every iteration | 4000 | Optional |
| query | The query used to search for IOCs in XSOAR (must include `-tags:xdr_pushed`) | reputation:Bad and (type:File or type:Domain or type:IP) and expirationStatus:active and -tags:xdr_pushed and -tags:xdr_not_processed | Required |
| query_expired | The query used to search for IOCs in XSOAR that were pushed into XDR (must include `tags:xdr_pushed`) | reputation:Bad and (type:File or type:Domain or type:IP) and expirationStatus:expired tags:xdr_pushed and -tags:xdr_disabled | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![XDR IOCs - Push new IOCs to XDR (main)](../doc_files/Cortex_XDR_IOCs_-_Push_new_IOCs_to_XDR_(main).png)
