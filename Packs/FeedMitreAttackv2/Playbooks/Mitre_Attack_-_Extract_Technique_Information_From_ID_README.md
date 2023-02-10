This playbook accepts as input MITRE techniques IDs.  
It returns the MITRE technique name and full technique data using the MITRE integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
FeedMitreAttackv2

### Scripts
This playbook does not use any scripts.

### Commands
* attack-pattern
* mitre-get-indicator-name

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TechniqueID | Accepts a single MITRE technique ID or array of technique IDs, for example: <br/>T1210 |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AttackPattern | Array of attack pattern names and IDs. | string |
| MITREATTACK | Full MITRE data for the attack pattern. | string |

## Playbook Image
---
![MITRE - Extract and Associate to Incident]!(../doc_files/Mitre_Attack _-_Extract_Technique_Information_From_ID.png)
