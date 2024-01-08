This playbook is used to initiate the processing of an incident. This playbook runs when a pending incident is selected for investigation. It will change the state from pending to active and it will list the available users in Vectra and request the user ID to use for assignment. Once the data collection is complete, it will call the Dispatch Incident - Vectra XDR playbook.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Dispatch Incident - Vectra XDR
* Add Note - Vectra XDR

### Integrations

* VectraXDR

### Scripts

* VectraXDRAddNotesInLayout
* DeleteContext

### Commands

* vectra-user-list

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Process Incident - Vectra XDR](../doc_files/Process_Incident_-_Vectra_XDR.png)
