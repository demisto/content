Get the incidents with the type Vectra RUX Events Detection.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| page | Provide the page number. Single page have max 50 incidents. |
| incident_type | Provide the incident type. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| VectraRUXGetIncidents.id | Incident ID. | String |
| VectraRUXGetIncidents.name | Incident name. | String |
| VectraRUXGetIncidents.CustomFields.vectraruxdetectionid | Vectra RUX detection ID linked to this incident. | String |
