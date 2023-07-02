Restricts the Incident Types a user can create manually, based on their assigned XSOAR Role(s). 

Requirements - Create an XSOAR List called IncidentTypeRBAC with the following structure, the names must match exactly to the names in the Incident Types under Settings!

Example List:
{
"Default":["Case","Job","Unclassified"],
"Analyst":["Phishing","Malware"],
"ThreatHunters":["Hunt"]
}

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | field-display |
| Cortex XSOAR Version | 6.5.0 |

## Inputs

---
There are no inputs for this script.

## Outputs

---
There are no outputs for this script.
