This playbook assists in processing an incident after it occurs and facilitates the lessons learned stage,
as described in the ‘Handling an Incident’ section of NIST - Computer Security Incident Handling Guide.
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf

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

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DataCollection | Use a data collection task to answer lessons learned questions based on NIST. Specify 'True' to automatically send the communication task, and 'False'  to prevent it. | True | Optional |
| Email | Email address to which to send the questions. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NIST - Lessons Learned.Answers.0 | Answer to communication task. | shortText |
| NIST - Lessons Learned.Answers.1 | Answer to communication task. | shortText |
| NIST - Lessons Learned.Answers.2 | Answer to communication task. | shortText |
| NIST - Lessons Learned.Answers.3 | Answer to communication task. | shortText |
| NIST - Lessons Learned.Answers.4 | Answer to communication task. | shortText |
| NIST - Lessons Learned.Answers.5 | Answer to communication task. | shortText |
| NIST - Lessons Learned.Answers.6 | Answer to communication task. | shortText |
| NIST - Lessons Learned.Answers.7 | Answer to communication task. | shortText |
| NIST - Lessons Learned.Answers.8 | Answer to communication task. | shortText |
| NIST - Lessons Learned.Answers.name | Provided username or email address | unknown |

## Playbook Image
---
![NIST_Lessons_Learned](https://raw.githubusercontent.com/demisto/content/e3151e10c150344c8bf99fcdcb3932919ebf7315/Packs/NIST/doc_files/Access_Investigation_Generic_NIST.png)
