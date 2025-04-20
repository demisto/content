Can be used to find duplicate emails for incidents of type phishing, including  malicious, spam, and legitimate emails.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml, phishing |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incidentTypeFieldName | The name of the incident field where its type is stored. Default is "type". Change this argument only in case you use a custom field for specifying incident type. |
| incidentTypes | A comma-separated list of incident types by which to filter. The default is the current incident type. Specify "None" to ignore incident type from deduplication logic. |
| existingIncidentsLookback | The start date by which to search for duplicated existing incidents. Date format is the same as in the incidents query page. For example, "3 days ago", "2019-01-01T00:00:00 \+0200"\). |
| query | Additional text by which to query incidents. |
| limit | The maximum number of incidents to fetch. |
| emailSubject | Subject of the email. |
| emailBody | Body of the email. |
| emailBodyHTML | HTML body of the email. |
| emailFrom | Incident fields contains the email from value. |
| fromPolicy | Whether to take into account the email from field for deduplication. "TextOnly" - incidents will be considered as duplicated based on test similarity only, ignoring the sender's address. "Exact" - incidents will be considered as duplicated if their text is similar and their sender is the same. "Domain" -  incidents will be considered as duplicated if their text is similar and their senders' address has the same domain. Default is "Domain". |
| statusScope | Whether to compare the new incident to past closed or non closed incidents only. |
| closeAsDuplicate | Whether to close the current incident if a duplicate incident is found. |
| threshold | Threshold to consider incident as duplication, number between 0-1 |
| maxIncidentsToReturn | Maximum number of duplicate incidents IDs to return. |
| populateFields | A comma-separated list of incident fields to populate. |
| exsitingIncidentsLookback | Deprecated. Use the \*existingIncidentsLookback\* argument instead. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| duplicateIncident | The oldest duplicate incident found with the highest similarity to the current incident. | unknown |
| duplicateIncident.id | Duplicate incident ID. | string |
| duplicateIncident.rawId | Duplicate incident ID. | Unknown |
| duplicateIncident.name | Duplicate incident name. | Unknown |
| duplicateIncident.similarity | Number in range 0-1 which describe the similarity between the existing incident and the new incident. | Unknown |
| isDuplicateIncidentFound | Whether a duplicate incident was found \("true" or "false"\). | boolean |
| allDuplicateIncidents | All duplicate incidents found where their similarity with the new incident exceeds the threshold. | Unknown |
| allDuplicateIncidents.id | A list of all duplicate incidents IDs found. | Unknown |
| allDuplicateIncidents.rawId | A list of all duplicate incidents IDs found. | Unknown |
| allDuplicateIncidents.name | A list of all duplicate incidents names found. | Unknown |
| allDuplicateIncidents.similarity | A list of the similarity between duplicate incidents and new the incident of all duplicate incidents names found. | Unknown |
