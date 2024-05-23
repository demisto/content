This playbook was developed as a template response when an Identity Exposure Playbook Alert has been triggered.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Active Directory Query v2
* IdentityRecordedFuturePlaybookAlerts
* Okta v2

### Scripts

* IsIntegrationAvailable

### Commands

* okta-suspend-user
* ad-get-user
* okta-add-to-group
* closeInvestigation
* okta-search
* ad-disable-account
* recordedfuture-identity-playbook-alerts-update
* ad-expire-password

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Recorded Future - Identity Exposure](../doc_files/Recorded_Future_-_Identity_Exposure.png)
