Designed to be invoked from CrowdStrike / SentinelOne / Defender alert playbooks. Takes the alert's IOCs, enriches each via Darkmon, and if any are scored Bad, escalates incident severity and notifies the SOC. Endpoint containment is left to the EDR-specific playbook.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Enrich IOCs via Darkmon (URL pass)
* Notify SOC

### Integrations

This playbook does not use any integrations.

### Scripts

* Set

### Commands

This playbook does not use any commands.

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore | Per-IOC reputation scores from Darkmon. | unknown |
