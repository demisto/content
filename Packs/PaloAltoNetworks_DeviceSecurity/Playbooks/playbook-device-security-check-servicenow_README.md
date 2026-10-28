This playbook checks the ServiceNow ticket status for Palo Alto Networks Device Security (previously Zingbox) alerts or vulnerabilities and automatically closes the Cortex XSOAR incident when the related ServiceNow ticket is closed. Designed to run as a recurring job.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* ServiceNow v2

### Scripts

* device-security-check-servicenow

### Commands

* closeInvestigation

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![PANW Device Security ServiceNow Tickets Check](../doc_files/device-security-check-servicenow.png)
