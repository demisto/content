Finds similar incidents based on indicators' similarity. Indicators' contribution to the final score is based on their scarcity.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Dedup - Generic v4

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incidentId | Incident ID to get the prediction of. If empty, predicts the current incident ID. |
| maxIncidentsInIndicatorsForWhiteList | The maximum number of incidents that an indicator can be associated with to be retained. This helps to filter out indicators that appear in many incidents  |
| minNumberOfIndicators | The minimum number of indicators related to the incident required before running the model. |
| threshold | Threshold to similarity value which is between 0 and 1. |
| indicatorsTypes | Type of indicators to take into account. If empty, uses all indicators types. |
| showActualIncident | Whether to show the incident you are investigating. |
| maxIncidentsToDisplay | The maximum number of incidents to display. |
| fieldsIncidentToDisplay | Fields to add in the table of incident |
| fromDate | The start date by which we retrieve information on incidents. |
| query | Argument for the query of similar incidents. |

## Outputs

---
There are no outputs for this script.
