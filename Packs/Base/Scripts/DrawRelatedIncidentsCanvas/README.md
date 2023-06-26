Draw incidents and indicators on the canvas to map and visualize their connections.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incidentID | Incident ID of the incident with which to update the canvas. If not specified, updates the current incident. |
| relatedIncidentsIDs | Incident IDs to draw on the canvas and relate to the main incident. The format can be a list of IDs or comma-separated values. |
| indicators | Indicators to draw on the canvas. The format is a list of indicator objects. |
| layout | The canvas layout. Can be "multipartite", "shell", "spring", "kamada_kawai", or "circular". |
| overrideUserCanvas | Override the canvas if it exists. |

## Outputs

---
There are no outputs for this script.
