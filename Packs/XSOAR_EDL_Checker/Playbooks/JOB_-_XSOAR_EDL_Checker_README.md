This playbook executes the XSOAR EDL Checker automation and will send email notification when an EDL is not functioning.   

Run this playbook as a job (hourly?) to monitor your EDLs.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* XSOARAllEDLCheckerAutomation

### Commands
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SendNotification | The comma separated list of email addresses to send notification to.  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
