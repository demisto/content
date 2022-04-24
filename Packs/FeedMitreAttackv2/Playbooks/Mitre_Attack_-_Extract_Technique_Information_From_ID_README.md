The playbook accepts as an input MITRE techniques ID's
provides the MITRE technique name and grabs all the technique data using the MITRE integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* FeedMitreAttackv2

### Scripts
This playbook does not use any scripts.

### Commands
* attack-pattern
* mitre-get-indicator-name

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TechniqueID | Accepts a single or array of MITRE technique ID's such as <br/>T1210 etc. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AttackPattern | Array of attack patterns name and ID's. | string |
| MITREATTACK | Full MITRE data for the attack pattern. | string |

## Playbook Image
---
![MITRE - Extract and Associate to Incident]!(../doc_files/Mitre_Attack _-_Extract_Technique_Information_From_ID.png)