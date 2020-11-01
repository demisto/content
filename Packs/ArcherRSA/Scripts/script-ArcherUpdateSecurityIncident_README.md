Simplifies the process of updating a new record in Archer. Fields can be added in the record as script arguments and/or in the code, and have a newly created record easily.

The automation fields are currently used for Archer application 75 (Security Incidents) but can be altered to any other application by modifying the fields in the code. 

Note - if the script is altered to work with another application some of the argument defined fields may need to be changed as they belong to application 75.
Another option would be to duplicate this script and adjust it to the new application ID.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags |  |


## Dependencies
---
This script uses the following commands and scripts.
* archer-update-record

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| description | The incident description. |
| dateTimeOccurred | The occurrence time of the incident. For example, "DateTimeOccurred="3/23/2018 7:00 AM"". |
| dateTimeIdentified | The identifying time of the incident. For example: DateTimeIdentified="3/23/2018 7:00 AM" |
| dateTimeReported | The reporting time of the incident. For example: DateTimeReported="3/23/2018 7:00 AM" |
| executiveSummary | The executive summary of the incident. |
| incidentReport | The incident's report. |
| incidentId | The archer incident ID. |
| contentId | The archer content ID. |

## Outputs
---
There are no outputs for this script.
