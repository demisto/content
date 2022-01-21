This playbook awaits job completion by continuously running get-job-status until the operation finishes.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Integrations
* AccessdataV2

## Commands
* accessdata-api-get-job-status

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| interval | The minutes between polls to the API. | Required |
| timeout | The minutes to timeout after. | Required |
| caseid | The identifying number for the case. | Required |
| jobid | The identifying number for the job task. | Required |

## Playbook Image
---
![AccessData__Job_Polling](https://user-images.githubusercontent.com/8157465/148918398-1998af8a-d6f2-4aeb-b1fe-61b0744b7277.png)
