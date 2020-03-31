Syncs and updates new XDR alerts that construct the incident. Thsi playbook enriches indicators using Threat Intelligence Integrations and Palo Alto Networks AutoFocus. The incident's severity is then updated based on the indicators reputation and an analyst is assigned for manual investigation. If chosen, automated remediation with Palo Alto Networks FireWall is initiated. After a manual review by the SOC analyst, the XDR incident is closed automatically. This playbook is triggered by fetching a Palo Alto Networks Cortex XDR incident. 

*** Note - The XDRSyncScript used by this playbook sets data in the XDR incident fields that were released to content from the Demisto server version 5.0.0.

For Demisto versions under 5.0.0, please follow the 'Palo Alto Networks Cortex XDR' documentation to upload the new fields manually.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* Calculate Severity - Standard
* Palo Alto Networks - Malware Remediation

## Integrations
* Builtin

## Scripts
* StopScheduledTask
* XDRSyncScript

## Commands
* xdr-update-incident
* closeInvestigation
* autofocus-sample-analysis

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

![Cortex_XDR_Incident_Handling](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Cortex_XDR_Incident_Handling.png)
