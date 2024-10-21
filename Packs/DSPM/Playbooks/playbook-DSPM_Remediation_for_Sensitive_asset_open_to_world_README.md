The DSPM Remediation Playbook for Sensitive Asset Open to World is designed to handle incidents where sensitive assets are exposed to the public, with specific focus on remediating this vulnerability across different cloud providers (AWS). Below is an overview of the key steps and actions included in this playbook:

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* AWS - S3
* DSPM

### Scripts

* DSPMIncidentList
* DSPMOverwriteListAndNotify
* DSPMCheckAndSetErrorEntries

### Commands

* dspm-update-risk-finding-status
* aws-s3-put-public-access-block

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![DSPM Remediation playbook for Sensitive asset open to world.](../doc_files/DSPM_Remediation_playbook_for_Sensitive_asset_open_to_world..png)
