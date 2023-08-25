Train clustering model on Cortex XDR incident type.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | widget |
| Cortex XSOAR Version | 6.2.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| returnWidgetType | The type of the widget to return. |
| fromDate | The start date by which to filter incidents. Date format will be the same as in the incidents query page, for example: "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| limit | The maximum number of incidents to fetch |
| incidentType | The Cortex XDR incident type |
| searchQuery | Input search query from the dashboard |
| modelExpiration | Period of time \(in hours\) before retraining the model. Default is "24". |
| forceRetrain | Determines whether to force the model to re-train. Default is "False". |
| fieldsToDisplay | Comma-separated list of additional incident fields to display, but which will not be taken into account when computing similarity. |

## Outputs

---
There are no outputs for this script.
