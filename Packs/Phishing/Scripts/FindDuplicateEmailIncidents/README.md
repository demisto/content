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
| existingIncidentsLookback | The start date by which to search for duplicated existing incidents. Date format is the same as in the incidents query page. For example, "3 days ago", "2019-01-01T00:00:00 \+0200"\). This is the correct argument to use; the misspelled \*exsitingIncidentsLookback\* argument is deprecated. |
| query | Additional text by which to query incidents. |
| limit | The maximum number of incidents to fetch. |
| emailSubject | The NAME of the incident field that holds the email subject \(for example, emailsubject\). Do not pass the field value \(for example, $\{incident.emailsubject\}\). Values containing whitespace or longer than 100 characters are ignored and the default field name is used. |
| emailBody | The NAME of the incident field that holds the email body \(for example, emailbody\). Do not pass the field value \(for example, $\{incident.emailbody\}\). Values containing whitespace or longer than 100 characters are ignored and the default field name is used. |
| emailBodyHTML | The NAME of the incident field that holds the email HTML body \(for example, emailbodyhtml\). Do not pass the field value \(for example, $\{incident.emailbodyhtml\}\). Values containing whitespace or longer than 100 characters are ignored and the default field name is used. |
| emailFrom | The NAME of the incident field that holds the email sender address \(for example, emailfrom\). Do not pass the field value \(for example, $\{incident.emailfrom\}\). Values containing whitespace or longer than 100 characters are ignored and the default field name is used. |
| fromPolicy | Whether to take into account the email from field for deduplication. "TextOnly" - incidents will be considered as duplicated based on test similarity only, ignoring the sender's address. "Exact" - incidents will be considered as duplicated if their text is similar and their sender is the same. "Domain" -  incidents will be considered as duplicated if their text is similar and their senders' address has the same domain. Default is "Domain". |
| statusScope | Whether to compare the new incident to past closed or non closed incidents only. |
| closeAsDuplicate | Whether to close the current incident if a duplicate incident is found. Only supported in Cortex XSOAR. |
| threshold | Threshold to consider incident as duplication, number between 0-1 |
| maxIncidentsToReturn | Maximum number of duplicate incidents IDs to return. |
| populateFields | A comma-separated list of incident fields to populate. |
| exsitingIncidentsLookback | Deprecated. Use the \*existingIncidentsLookback\* argument instead. This argument is ignored by the script. |

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
