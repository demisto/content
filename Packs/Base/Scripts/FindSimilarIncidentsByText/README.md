Find similar incidents by text comparison - the algorithm based on TF-IDF method.
To read more about this method: https://en.wikipedia.org/wiki/Tf%E2%80%93idf

This automation runs using the default Limited User role, unless you explicitly
change the permissions.
For more information, see the section about permissions here:
https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml, dedup, duplicate, incidents |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Dedup - Generic
* Dedup - Generic v2
* Dedup - Generic v3

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| textFields | Text fields to compare. Can be label name, incident fields or custom fields. Comma separated value.  |
| threshold | TFIDF score threshold \(to consider incident as similar\). |
| maximumNumberOfIncidents | Maximum number of incidents to check. |
| timeFrameHours | Check incidents in this time frame. |
| ignoreClosedIncidents | Ignore close incidents. |
| timeField | Time field to consider. |
| maxResults | Maximum number of similar candidates. |
| minTextLength | Minimum required text length to compare. |
| preProcessText | Whether to pre-process text \(removing HTML, normilize words\) |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| similarIncident.rawId | Similar incident ID. | string |
| isSimilarIncidentFound | Is similar incident found? \(true\\false\) | boolean |
| similarIncident | Similar incident. | Unknown |
| similarIncident.name | Similar incident name. | string |
