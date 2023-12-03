This playbook is part of the Cortex XDR by Palo Alto Networks’ pack. This playbook searches alerts related to specific entities from Cortex XDR, on a given timeframe, based on MITRE tactics.
Note: The playbook's inputs enable manipulating the execution flow. Read the input descriptions for details.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CortexXDRIR

### Scripts

* CountArraySize
* SetAndHandleEmpty

### Commands

* xdr-get-alerts

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| HuntReconnaissanceTechniques | Set to True to hunt for identified alerts with MITRE Reconnaissance techniques. | False | Optional |
| HuntInitialAccessTechniques | Set to True to hunt for identified alerts with MITRE Initial Access techniques. | False | Optional |
| HuntExecutionTechniques | Set to True to hunt for identified alerts with MITRE Execution techniques. | False | Optional |
| HuntPersistenceTechniques | Set to True to hunt for identified alerts with MITRE Persistence techniques. | False | Optional |
| HuntPrivilegeEscalationTechniques | Set to True to hunt for identified alerts with MITRE Privilege Escalation techniques. | False | Optional |
| HuntDefenseEvasionTechniques | Set to True to hunt for identified alerts with MITRE Defense Evasion techniques. | False | Optional |
| HuntDiscoveryTechniques | Set to True to hunt for identified alerts with MITRE Discovery techniques. | False | Optional |
| HuntLateralMovementTechniques | Set to True to hunt for identified alerts with MITRE Lateral Movement techniques. | False | Optional |
| HuntCollectionTechniques | Set to True to hunt for identified alerts with MITRE Collection techniques . | False | Optional |
| HuntCnCTechniques | Set to True to hunt for identified alerts with MITRE Command and Control techniques. | False | Optional |
| HuntImpactTechniques | Set to True to hunt for identified alerts with MITRE Impact techniques. | False | Optional |
| HuntCredentialAccessTechniques | Set to True to hunt for identified alerts with MITRE Credential Access techniques. | False | Optional |
| timeRange | A time range to execute the hunting in.<br/>The input should be in the following format:<br/>\* 1 day<br/>\* 2 minutes<br/>\* 4 hours<br/>\* 8 days | 6 hours | Optional |
| RunAll | Whether to run all the sub-tasks for Mitre Tactics. | True | Optional |
| EntityType | Entity type to search on xdr-get-alerts custom filters. |  | Optional |
| entityID | Entity value. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Alert | Alerts found. | unknown |
| ArraySize | Array size. | unknown |

## Playbook Image

---

![Cortex XDR - Get entity alerts by MITRE tactics](../doc_files/Cortex_XDR_-_Get_entity_alerts_by_MITRE_tactics.png)
