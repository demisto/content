This playbook is part of the 'Malware Investigation And Response' pack. For more information, refer to https://xsoar.pan.dev/docs/reference/packs/malware-investigation-and-response.
This playbook handles all the endpoint investigation actions available with Cortex XSOAR, including the following tasks:
* Pre-defined MITRE Tactics
* Host fields (host ID)
* Attacker fields (attacker IP, external host)
* MITRE techniques
* File hash (currently, the playbook supports only SHA256)  

**Note:**  
The playbook inputs enable manipulating the execution flow; read the input descriptions for details.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
CortexXDRIR

### Scripts
This playbook does not use any scripts.

### Commands
xdr-get-alerts

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| HuntReconnaissanceTechniques | Whether to hunt for identified alerts with MITRE Reconnaissance techniques. | True | Optional |
| HuntInitialAccessTechniques | Whether to hunt for identified alerts with MITRE Access techniques. | True | Optional |
| HuntExecutionTechniques | Whether to hunt for identified alerts with MITRE Execution techniques. | True | Optional |
| HuntPersistenceTechniques | Whether to hunt for identified alerts with MITRE Persistence techniques. | True | Optional |
| HuntPrivilegeEscalationTechniques | Whether to hunt for identified alerts with MITRE Privilege Escalation techniques. | True | Optional |
| HuntDefenseEvasionTechniques | Whether to hunt for identified alerts with MITRE Defense Evasion techniques. | True | Optional |
| HuntDiscoveryTechniques | Whethere to hunt for identified alerts with MITRE Discovery techniques. | True | Optional |
| HuntLateralMovementTechniques | Whether to hunt for identified alerts with MITRE Lateral Movement techniques. | True | Optional |
| HuntCollectionTechniques | Whether to hunt for MITRE Collection techniques identified alerts. | True | Optional |
| HuntCnCTechniques | Whether to hunt for identified alerts with MITRE Command and Control techniques. | True | Optional |
| HuntImpactTechniques | Whether to hunt for identified alerts with MITRE Impact techniques. | True | Optional |
| HuntAttacker | Whether to hunt the attacker IP address or external hostname. |  | Optional |
| HuntByTechnique | Whether to hunt by a specific MITRE technique. |  | Optional |
| HuntByHost | Whether to hunt by the endpoint ID. The agentID input must be provided as well. |  | Optional |
| HuntByFile | Whether to hunt by a specific file hash.<br/>Supports SHA256. |  | Optional |
| agentID | The agent ID. | incident.agentsid | Optional |
| attackerRemoteIP | The IP address of the attacker. The 'HuntAttacker' inputs should also be set to True. |  | Optional |
| attackerExternalHost | The external host used by the attacker. The 'HuntAttacker' inputs should also be set to True. |  | Optional |
| mitreTechniqueID | A MITRE technique identifier. The 'HuntByTechnique' inputs should also be set to True. |  | Optional |
| FileSHA256 | The file SHA256. The 'HuntByFile' inputs should also be set to True. | File.SHA256 | Optional |
| timeRange | A time range to execute the hunting in.<br/>The input should be in the following format:<br/>\* 1 day ago<br/>\* 2 minutes ago<br/>\* 4 hours ago<br/>\* 8 days ago | 2 hours ago | Optional |
| RunAll | Whether to run all the sub-tasks for Mitre Tactics. | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Endpoint Investigation](../doc_files/Cortex_XDR_-_Endpoint_Investigation.png)
