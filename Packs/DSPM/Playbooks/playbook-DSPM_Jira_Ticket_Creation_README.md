The DSPM Jira Ticket Creation is designed as a sub-playbook for Jira Ticket Creation, streamlining the process of creating a Jira ticket and providing immediate notification to the user with ticket details upon successful creation. If an error occurs during ticket creation, the user receives a notification containing relevant incident details.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* DSPM notify user in case of error

### Integrations

This playbook does not use any integrations.

### Scripts

* DSPMCheckAndSetErrorEntries
* DSPMOverwriteListAndNotify

### Commands

* setIncident
* jira-create-issue

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![DSPM Jira Ticket Creation](../doc_files/DSPM_Jira_Ticket_Creation.png)
