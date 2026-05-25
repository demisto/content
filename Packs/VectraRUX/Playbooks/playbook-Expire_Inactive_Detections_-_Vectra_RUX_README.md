This playbook identifies incidents with inactive detections and updates their investigation status to "expired".

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Find Detection State and Expire Inactive Detections - Vectra RUX

### Integrations

This playbook does not use any integrations.

### Scripts

* DeleteContext

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident_type | The XSOAR incident type to search for inactive detections. Default is 'Vectra RUX Events Detection'. | Vectra RUX Events Detection | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Vectra.Detection.id | The detection ID. | String |
| Vectra.Detection.investigation_status | The detection investigation status. | String |

## Playbook Image

---

![Expire Inactive Detections - Vectra RUX](../doc_files/Expire_Inactive_Detections_-_Vectra_RUX.png)
