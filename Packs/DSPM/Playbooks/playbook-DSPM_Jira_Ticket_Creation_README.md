This playbook automates the process of creating and managing Jira issues for DSPM-related risks detected in XSOAR incidents. It creates a Jira ticket with risk details, checks for errors, updates incident details, and sends a Slack notification with ticket information. This streamlines risk tracking and notification.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* DSPM notify user in case of error

### Integrations

This playbook does not use any integrations.

### Scripts

* DSPMCreateSimpleSlackMessageBlock
* DSPMCheckAndSetErrorEntries
* DeleteContext

### Commands

* setIncident
* setList
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
