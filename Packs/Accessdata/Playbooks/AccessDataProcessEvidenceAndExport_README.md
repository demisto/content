Processes an evidence file and exports the items responsive to a filter.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* AccessDataJobPolling

## Integrations
* AccessdataV2

## Commands
* accessdata-api-get-case-by-name
* accessdata-api-process-evidence
* accessdata-api-export-natives
* accessdata-api-create-filter
* accessdata-api-get-job-status

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| casename | The name of the case to add evidence too. | Required |
| processingoptions | The processing options to supply to the engine. | Required |
| evidencepath | The path to the evidence object to process. | Required |
| destinationpath | The directory to export native files too. | Required |

## Playbook Image
---
![AccessDataProcessEvidenceAndExport](https://user-images.githubusercontent.com/8157465/146163898-52b9b0df-3a3c-4b63-a6ca-6813395a7d6b.png)
