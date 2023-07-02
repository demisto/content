Playbook for retrieving credentials for BeyondTrust Password Safe 

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* BeyondTrust Password Safe

### Scripts

* Set

### Commands

* beyondtrust-get-managed-accounts
* beyondtrust-get-credentials
* beyondtrust-list-release-requests
* beyondtrust-create-release-request

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BeyondTrust.Account.AccountName | Name of the managed account. | unknown |
| BeyondTrust.Account.AccountID | ID of the managed account. | unknown |
| BeyondtrustAccountCredentials | Account credentials | unknown |
