This playbook support 3 different actions for the analyst:
- Run Full AV scan for spesific enpoint
- Request Investigation Package (zip file that contains forensic data - with a size of ~ 15MB) from an endpoint.
- Request to run Automatic Investigation on an endpoint.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* MDE - Collect Investigation Package

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
This playbook does not use any scripts.

### Commands
* microsoft-atp-start-investigation
* microsoft-atp-run-antivirus-scan

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Task | Option for input \( can be entered as comma-separated values\):<br/>\`Full Scan\` - Fully Scan the provided endpoint/s<br/>\`Collect Investigation Package\` - Collect investigation package from endpoint/s \(only for supported devices\)<br/>\`Automated Investigation\` - Run Automated Investigation on the provided endpoint |  | Optional |
| Endpoints ID | Provide a list of endpoints for the Scan and Collection of investigation Package to be run on. |  | Optional |
| AutoCollectinvestigationPackege | True/Fasle | False | Optional |
| AutoAVScan | True/Fasle | False | Optional |
| AutoAutomatedInvestigation | True/Fasle | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Pro-Active Actions](Insert the link to your image here)