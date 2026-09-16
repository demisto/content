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
| page | Provide the page number. A single page has a maximum of 50 incidents. |
| incident_type | The XSOAR incident type to search for inactive detections. Default is 'Vectra RUX Events Detection'. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| VectraRUXGetIncidents.id | Incident ID. | String |
| VectraRUXGetIncidents.name | Incident name. | String |
| VectraRUXGetIncidents.CustomFields.vectraruxdetectionid | Vectra RUX detection ID linked to this incident. | String |
