This playbook demonstrates sub-playbook looping using a for each method.  

We start by setting an array to a context key that we are going to loop over.  The array is a list of dictionaries with or without a base64 encoded string. 

We pass this into the sub-playbook to loop over, decode the string and return the original and decoded value. 

Individual steps in the playbook may have additional details. 

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* XSOAR Engineer Training - For Each Loops (Sub-Playbook)

### Integrations

This playbook does not use any integrations.

### Scripts

* Print
* DeleteContext
* Set

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

![XSOAR Engineer Training - For Each Loops (Parent)](../doc_files/XSOAR_Engineer_Training_-_For_Each_Loops_(Parent).png)
