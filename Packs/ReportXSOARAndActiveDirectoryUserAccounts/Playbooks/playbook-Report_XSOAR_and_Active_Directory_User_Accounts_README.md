Playbook to take account of local XSOAR Users compared to Active Directory XSOAR Users. 

Playbook runs in demo or regular mode, this is a data point which should be specified by the admin before first running the playbook. If unsure, demo mode allows using the XSOAR Engineer Training integration for testing purposes. 

It works by calling upon the XSOAR API for an account of the existing users, and also calls upon the Active Directory integration to request all users who have XSOAR permissions. Data is then displayed for analysis. There are three possible outcomes: nothing should be edited, we should delete the selected XSOAR users, or we should email the Active Directory administrator to create additional user accounts.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* XSOAREngineerTrainingCopy
* XSOAR Engineer Training_copy

### Scripts

* CustomDeleteUsersUsingCoreAPI
* RemoveItemFromList
* Set

### Commands

* ad-get-user
* send-mail
* getUsers
* closeInvestigation
* xet-ad-get-user

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Admin | Email to send notice to create new AD users is missing |  | Required |
| Demo Mode | Update the using instance as needed under the Advanced tab for better results. Uses the XSOAR Engineering Training integration to simulate the AD query to perform. | True | Optional |
| AD User | Provide if available |  | Optional |
| AD User Email | Provide if available |  | Optional |
| Distinguished Name | Provide if available |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Report XSOAR and Active Directory User Accounts](../doc_files/Report_XSOAR_and_Active_Directory_User_Accounts.png)
