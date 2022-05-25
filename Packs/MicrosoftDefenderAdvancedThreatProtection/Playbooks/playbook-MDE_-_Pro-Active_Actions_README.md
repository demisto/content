This playbook support 3 different actions for the analyst:
- Run Full AV scan for spesific enpoint
- Request Investigation Package (zip file that contains forensic data - with a size of ~ 15MB) from an endpoint.
- Request to run Automatic Investigation on an endpoint.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* 8d6603be-227b-48fb-8f77-0b0ff3d572db

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
This playbook does not use any scripts.

### Commands
* microsoft-atp-run-antivirus-scan
* microsoft-atp-start-investigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Task | Option for input \( can be entered as comma-separated values\):<br/>\`Full Scan\` - Fully Scan the provided endpoint/s<br/>\`Collect Investigation Package\` - Collect investigation package from endpoint/s \(only for supported devices\)<br/>\`Automated Investigation\` - Run Automated Investigation on the provided endpoint |  | Optional |
| EndpointsID | Provide a list of endpoints for the Scan and Collection of investigation Package to be run on. |  | Optional |
| AutoCollectinvestigationPackege | True/Fasle | True | Optional |
| AutoAVScan | True/Fasle | True | Optional |
| AutoAutomatedInvestigation | True/Fasle | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Pro-Active Actions](../doc_files/MDE_-_Pro-Active_Actions.png)