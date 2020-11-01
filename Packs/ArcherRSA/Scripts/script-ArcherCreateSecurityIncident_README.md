Simplifies the process of creating a new record in Archer. Fields can be added in the record as script arguments and/or in the code, and create a new record.

This automation is currently used for Archer application 75 (Security Incidents), but can be altered to any other application by entering another applications ID as input and/or modifying the default `ApplicationId` value in the arguments. 
Another option would be to duplicate this script and adjust it to the new application Id.

Note - If you alter the script to work with another application some of the argument defined fields may need to be changed as well, since they belong to application 75.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags |  |


## Dependencies
---
This script uses the following commands and scripts.
* archer-create-record

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| description | The incident description. |
| dateTimeOccurred | The occurrence time of the incident. For example, DateTimeOccurred="3/23/2018 7:00 AM". |
| dateTimeIdentified | The identifying time of the incident. For example, DateTimeIdentified="3/23/2018 7:00 AM". |
| dateTimeReported | The reporting time of the incident. For example, DateTimeReported="3/23/2018 7:00 AM". |
| executiveSummary | The executive summary of the incident. |
| incidentReport | The incident's report. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Archer.Record.Id | The content ID of the new record. | number |
