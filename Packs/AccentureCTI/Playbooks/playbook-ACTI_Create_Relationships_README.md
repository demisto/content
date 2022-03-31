Helps in creating relationships between indicators and reports.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Exists
* GetIndicatorDBotScore
* CreateIndicatorRelationship

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | The extracted IP address. | ${IP.Address} | Optional |
| IA | The Intelligence Alert uuid. | ${intelligence_alerts}.None | Optional |
| IR | The Intelligence Report uuid. | ${intelligence_reports}.None | Optional |
| URL | The extracted URL. | ${URL.Data} | Optional |
| Domain | The extracted Domain. | ${Domain.Name} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![ACTI Create Relationships](https://user-images.githubusercontent.com/40510780/161067875-ec2a5c31-f6b8-4cc7-90ce-9404e0cff36c.png)
![image](https://user-images.githubusercontent.com/40510780/161068348-1cfedccc-0497-470d-b59c-c1e4b67fbdbf.png)
![image](https://user-images.githubusercontent.com/40510780/161068641-12906d7b-d74e-49ac-ba62-a94911143577.png)
