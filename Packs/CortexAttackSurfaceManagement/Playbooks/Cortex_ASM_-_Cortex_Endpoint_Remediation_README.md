This playbook is used to isolate a single Cortex Endpoint (XSIAM/XDR) for remediation purposes.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Cortex Core - IR
* Cortex XDR - IR

### Scripts

* Set

### Commands

* xdr-endpoint-isolate
* core-isolate-endpoint

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| CortexEndpointID | The ID of the Cortex Endpoint \(XDR\). |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Cortex Endpoint Remediation](../doc_files/Cortex_ASM_-_Cortex_Endpoint_Remediation.png)
