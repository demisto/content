This playbook handles all the endpoint investigation actions available with XSIAM.
The playbook allows to investigate and hunt for more information using one of the following tasks:
* Pre-defined MITRE Tactics
* Host fields (Host ID)
* Attacker fields (Attacker IP, External host)
* MITRE techniques
* File hash (currently, the playbook supports only SHA256)

The playbook inputs allows you to manipulate the execution flow, please pay attention to the inputs description.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* SearchIncidentsV2

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| HuntReconnaissanceTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Reconnaissance techniques. | True | Optional |
| HuntInitialAccessTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Access techniques. | True | Optional |
| HuntExecutionTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Execution techniques. | True | Optional |
| HuntPersistenceTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Persistence techniques. | True | Optional |
| HuntPrivilegeEscalationTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Privilege Escalation techniques. | True | Optional |
| HuntDefenseEvasionTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Defense Evasion techniques. | True | Optional |
| HuntDiscoveryTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Discovery techniques. | True | Optional |
| HuntLateralMovementTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Lateral Movement techniques. | True | Optional |
| HuntCollectionTechniques | Boolean. Set to 'true' if you want to hunt for MITRE Collection techniques identified alerts. | True | Optional |
| HuntCnCTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Command and Control techniques. | True | Optional |
| HuntImpactTechniques | Boolean. Set to 'true' if you want to hunt for identified alerts with MITRE Impact techniques. | True | Optional |
| HuntAttacker | Boolean. Set to 'true' if you want to hunt the attacker IP address or external hostname. |  | Optional |
| HuntByTechnique | Boolean. Set to 'true' if you want to hunt by a specific MITRE technique. |  | Optional |
| HuntByHost | Boolean. Set to 'true' if you want to hunt by the endpoint ID. The agentID input must be provided as well. |  | Optional |
| HuntByFile | Boolean. Set to 'true' if you want to hunt by a specific file hash.<br/>Supports SHA256. |  | Optional |
| agentID | The agent ID. | * | Optional |
| attackerRemoteIP | The IP address of the attacker. The 'HuntAttacker' inputs should also be set to 'true'. |  | Optional |
| attackerExternalHost | The external host used by the attacker. The 'HuntAttacker' inputs should also be set to 'true'. |  | Optional |
| mitreTechniqueID | A MITRE technique identifier. The 'HuntByTechnique' inputs should also be set to 'true'. |  | Optional |
| FileSHA256 | The file SHA256. The 'HuntByFile' inputs should also be set to 'true'. |  | Optional |
| timeRange | A time range to execute the hunting over.<br/>The input should be in the following format:<br/>\* 1 day ago<br/>\* 2 minutes ago<br/>\* 4 hours ago<br/>\* 8 days ago<br/>etc. | 24 hours ago | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Endpoint Investigation Plan](https://raw.githubusercontent.com/demisto/content/f3d7d9140f4d82efde1704ed92b8de3176c35b2e/Packs/CommonPlaybooks/doc_files/Endpoint_Investigation_Plan.png)