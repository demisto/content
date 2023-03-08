This playbook demonstrates playbook looping via the embedded sub-playbook.  In this case, we query for a list of users to lookup, and pass them into the sub-playbook.  

The sub-playbook will check to see if the user exists in AD or not, and return a list of users who do exist, and those who don't as outputs which we can use in further parts of our parent playbook.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* XSOAR Engineer Training - AD User Lookup (Sub-Playbook)

### Integrations

This playbook does not use any integrations.

### Scripts

* DeleteContext
* Print

### Commands

This playbook does not use any commands.

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![XSOAR Engineer Training - AD User Lookup (Parent)](../doc_files/XSOAR_Engineer_Training_-_AD_User_Lookup_(Parent).png)
