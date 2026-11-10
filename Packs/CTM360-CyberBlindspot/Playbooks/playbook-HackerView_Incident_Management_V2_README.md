This playbook runs the incidents through indicator enrichment, then based on the mirroring settings, it can communicate with the remote server to track the progress of the investigation.

When the remote HackerView ticket status becomes **inactive**, the playbook automatically closes the local incident (`Close Incident Locally` → `closeInvestigation`). The HackerView Incident type runs this playbook with **autorun** enabled, so that auto-close path does not wait for analyst input.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Entity Enrichment - Generic v3

### Integrations

* CTM360_HackerView

### Scripts

* AssignAnalystToIncident
* GetEnabledInstances
* IsIntegrationAvailable

### Commands

* closeInvestigation
* ctm360-hv-incident-details
* ctm360-hv-incident-status-change

## Playbook Inputs

---
| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| closeReason | The reason recorded when the playbook closes the local incident after the remote HackerView ticket becomes inactive. | Incident closed by DBot via playbook | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![HackerView Incident Management V2](../doc_files/HackerView_Incident_Management_V2.png)
