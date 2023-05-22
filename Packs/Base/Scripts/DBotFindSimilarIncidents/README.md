Find past similar incidents based on incident fields' similarity. Includes an option to also display indicators similarity.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Cortex XDR incident handling v3
* Dedup - Generic v4
* Endpoint Malware Investigation - Generic V2

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incidentId | Incident ID to get the prediction of. If empty, predicts the the current incident ID. |
| similarTextField | Comma-separated list of incident text fields to take into account when computing similarity. For example: commandline, URL |
| similarCategoricalField | Comma-separated list of incident categorical fields to take into account whe computing similarity. For example: IP, URL |
| similarJsonField | Comma-separated list of incident JSON fields to take into account whe computing similarity. For example: CustomFields |
| fieldsToDisplay | Comma-separated list of additional incident fields to display, but which will not be taken into account when computing similarity. |
| fieldExactMatch | Comma-separated list of incident fields that have to be equal to the current incident fields. This helps reduce the query size. |
| useAllFields | Whether to use a predefined set of fields and custom fields to compute similarity. If "True", it will ignore values in similarTextField, similarCategoricalField, similarJsonField. |
| fromDate | The start date by which to filter incidents. Date format will be the same as in the incidents query page, for example, "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| toDate | The end date by which to filter incidents. Date format will be the same as in the incidents query page, for example, "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| query | Argument for the query. This helps reduce the query size. |
| limit | The maximum number of incidents to query. |
| aggreagateIncidentsDifferentDate | Whether to aggregate duplicate incidents within diffrerent dates. |
| showIncidentSimilarityForAllFields | Whether to display the similarity score for each of the incident fields. |
| minimunIncidentSimilarity | Retain incidents with similarity score that's higher than the MinimunIncidentSimilarity. |
| maxIncidentsToDisplay | The maximum number of incidents to display. |
| showCurrentIncident | Whether to display the current incident. |
| includeIndicatorsSimilarity | Whether to include similarity of indicators from DBotFindSimilarIncidentsByIndicators in the final score. |
| minNumberOfIndicators | The minimum number of indicators required related to the incident before running the model. Relevant if includeIndicatorsSimilarity is "True". |
| indicatorsTypes | Comma-separated list of indicator types to take into account. If empty, uses all indicators types. Relevant if includeIndicatorsSimilarity is "True". |
| maxIncidentsInIndicatorsForWhiteList | Help to filter out indicators that appear in many incidents. Relevant if includeIndicatorsSimilarity is "True". |

## Outputs

---
There are no outputs for this script.
