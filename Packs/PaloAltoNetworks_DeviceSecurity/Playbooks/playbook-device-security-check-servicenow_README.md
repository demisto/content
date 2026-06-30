This playbook checks the ServiceNow ticket status for Palo Alto Networks Device Security (previously Zingbox) alerts or vulnerabilities. Designed to run as a recurring job.

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
| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| CloseReason | The close reason passed to closeInvestigation when incidents are closed by this playbook. | Other | Optional |
| CloseNotes | The close notes passed to closeInvestigation when incidents are closed by this playbook. | Job finished | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---
![Palo_Alto_Neworks_Device_Security_ServiceNow_Check](../doc_files/device-security-check-servicenow.png)
