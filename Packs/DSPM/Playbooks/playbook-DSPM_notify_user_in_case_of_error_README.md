The DSPM Notify User in Case of Error playbook is designed to handle errors in DSPM incidents by notifying users and managing Slack notifications.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* DSPMIncidentList
* SetIfEmpty
* DeleteContext
* SlackBlockBuilder
* DSPMCreateSimpleSlackMessageBlock

### Commands

* createList
* getList
* setList
* core-api-post
* addToList

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| rerunTime | Incident re-run time \(in hours\) |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![DSPM notify user in case of error](../doc_files/DSPM_notify_user_in_case_of_error.png)
