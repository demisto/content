This playbook adds new block rule(s) to on-prem firewall vendors in order to block internet access for internet exposures.

Conditions:
This is currently limited to stand-alone firewalls for PAN-OS.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* PAN-OS - Block Destination Service

### Integrations

* Panorama

### Scripts

This playbook does not use any scripts.

### Commands

* pan-os-list-rules

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RuleName | Firewall rule name to look up in the company configuration setting for block rule. |  | Required |
| RemoteIP | IP address of the service. | alert.remoteip | Required |
| RemoteProtocol | Protocol of the service. | alert.appid | Required |
| RemotePort | Port number of the service. | alert.remoteport | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - On Prem Remediation](../doc_files/Cortex_ASM_-_On_Prem_Remediation.png)
