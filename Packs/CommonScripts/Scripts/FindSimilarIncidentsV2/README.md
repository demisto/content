Deprecated. Use DBotFindSimilarIncidents instead.

Finds similar incidents by common incident keys, labels, custom fields or context keys.
It's highly recommended to use incident keys if possible (e.g., "type" for the same incident type).
For best performance, it's recommended to avoid using context keys if possible (for example, if the value also appears in a label key, use label).

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | dedup, duplicate, incidents |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Cortex XDR incident handling v2
* DeDup incidents
* Dedup - Generic
* Dedup - Generic v2
* Dedup - Generic v3
* Handle Darktrace Model Breach
* JOB - Integrations and Incidents Health Check
* Palo Alto Networks - Endpoint Malware Investigation v2
* Palo Alto Networks - Endpoint Malware Investigation v3
* Shift handover

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| similarIncidentKeys | A comma-separated list of identical incident keys. |
| similarLabelsKeys | A comma-separated list of similar label keys. Comma separated value. Also supports allowing X different words between labels, within the following way: label_name:X, where X is the number of words. X can also be '\*' for contains. For example: the value "Email/subject:\*" will consider  email subject similar, if one is substring of the other. |
| similarContextKeys | A comma-separated list of similar context keys. Also supports allowing X different words between values \(see the labels description\). |
| similarCustomFields | A comma-separated list of Similar custom fields keys. Also supports allowing X different words between values \(see the labels description\). |
| ignoreClosedIncidents | Whether to ignore closed incidents as duplicate candidates. Can be "yes" \(ignore\) or "no" \(don't ignore\). The default value is "yes". |
| maxNumberOfIncidents | Maximum number of incidents to query. |
| hoursBack | Query incidents in the last X hours. Supports float value. |
| timeField | Filter incidents by this time field. |
| maxResults | Maximum number of results to display. |
| similarIncidentFields | A comma-separated list of similar incident fields keys. Also supports allowing X different words between values \(see the labels description\). |
| filterQuery | Use this query condition when fetching duplicate incidents. |
| incidentFieldsAppliedCondition | The condition to apply between incident fields. Can be "OR" or "AND". This will apply only for fields with "exact match". |
| skipMissingValues | Whether to skip the incident if it does not have specific key. Can be "yes" \(skip\) or "no" \(don't skip\). The default value is "yes". WARNING: if no fields exist in the incident, random incidents might be returned as results due to the empty condition. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| similarIncident.rawId | Similar incident ID. | string |
| isSimilarIncidentFound | Whether a similar incident was found \("true" or "false"\). | boolean |
| similarIncident | Similar incident. | unknown |
| similarIncident.name | Similar incident name. | string |
