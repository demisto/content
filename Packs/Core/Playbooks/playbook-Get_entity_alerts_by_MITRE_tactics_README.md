This playbook searches XDR alerts related to specific entities , on a given timeframe, based on MITRE tactics.
Note: The playbook's inputs enable manipulating the execution flow. Read the input descriptions for details.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* SearchAlertsV2

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| HuntReconnaissanceTechniques | Set to True to hunt for identified alerts with MITRE Reconnaissance techniques. |  | Optional |
| HuntInitialAccessTechniques | Set to True to hunt for identified alerts with MITRE Initial Access techniques. |  | Optional |
| HuntExecutionTechniques | Set to True to hunt for identified alerts with MITRE Execution techniques. |  | Optional |
| HuntPersistenceTechniques | Set to True to hunt for identified alerts with MITRE Persistence techniques. |  | Optional |
| HuntPrivilegeEscalationTechniques | Set to True to hunt for identified alerts with MITRE Privilege Escalation techniques. |  | Optional |
| HuntDefenseEvasionTechniques | Set to True to hunt for identified alerts with MITRE Defense Evasion techniques. |  | Optional |
| HuntDiscoveryTechniques | Set to True to hunt for identified alerts with MITRE Discovery techniques. |  | Optional |
| HuntLateralMovementTechniques | Set to True to hunt for identified alerts with MITRE Lateral Movement techniques. |  | Optional |
| HuntCollectionTechniques | Set to True to hunt for identified alerts with MITRE Collection techniques . |  | Optional |
| HuntCnCTechniques | Set to True to hunt for identified alerts with MITRE Command and Control techniques. |  | Optional |
| HuntImpactTechniques | Set to True to hunt for identified alerts with MITRE Impact techniques. |  | Optional |
| HuntCredentialAccessTechniques | Set to True to hunt for identified alerts with MITRE Credential Access techniques. |  | Optional |
| timeRange | A time range to execute the hunting in.<br/>The input should be in the following format:<br/>\* 1 day<br/>\* 2 minutes<br/>\* 4 hours<br/>\* 8 days | 20 days | Required |
| RunAll | Whether to run all the sub-tasks for Mitre Tactics. | true | Optional |
| EntityType | Entity type to search. Entity type can be username, hostname, or any other element that exists in the alert. | hostname | Required |
| EntityID | Entity value. | None | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| foundIncidents | Alerts found | unknown |

## Playbook Image

---

![Get entity alerts by MITRE tactics](../doc_files/Get_entity_alerts_by_MITRE_tactics.png)
