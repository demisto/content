This playbook investigate a scan where the source is an internal IP address.

An attacker might initiate an internal scan for discovery, lateral movement and more.

**Attacker's Goals:**

An attacker can leverage a scan for open ports and vulnerable systems on remote endpoints in an attempt to identify the endpoint operating system, firewall configuration, and exploitable services.

**Investigative Actions:**

* Endpoint Investigation Plan playbook

**Response Actions:**

* Endpoint isolation
* Block indicators

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Account Enrichment - Generic v2.1
* Endpoint Investigation Plan
* Get endpoint details - Generic
* Containment Plan

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| scannerIP | The source IP address of the attacker. | alert.hostip | Optional |
| AutoCloseAlert | Whether to close the alert automatically or manually after an analyst's review. | false | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![NGFW Internal Scan](Insert the link to your image here)