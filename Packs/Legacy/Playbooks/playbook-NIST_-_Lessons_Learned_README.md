Assists in post-processing of an incident and facilitates the lessons learned stage, as presented by [SANS Institute ‘Incident Handler’s Handbook’ by Patrick Kral](https://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901).

***Disclaimer: This playbook does not ensure compliance to SANS regulations.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- | 
| DataCollection | The data collection to use to task to answer lessons learned questions based on SANS. Select "True" to automatically send the communication task, and "False"  to prevent it. | Optional |
| Email | The email address to send the questions to.  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SANS - Lessons Learned.Answers.0 | The time and  person to first detect the problem. | longText |
| SANS - Lessons Learned.Answers.1 | The scope of the incident. | longText |
| SANS - Lessons Learned.Answers.2 | Whether the incident was contained and eradicated. | longText |
| SANS - Lessons Learned.Answers.3 | The work performed during recovery. | longText |
| SANS - Lessons Learned.Answers.4 | The areas where the CIRT teams was effective. | longText |
| SANS - Lessons Learned.Answers.5 | The areas that need improvement. | longText |
| SANS - Lessons Learned.Answers.6 | Share ideas and information in order to improve team effectiveness in future incidents. | longText |
| SANS - Lessons Learned.Answers.name | The returned username or email address. | unknown |

## Playbook Image
---
![NIST_Lessons_Learned](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/NIST_Lessons_Learned.png)
