Handles each fetched Darktrace model breach by gathering additional detail about the activity through enrichment data from Darktrace and XSOAR. Additionally, it offers the ability to take proactive actions from XSOAR to your Darktrace deployment.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Entity Enrichment - Generic v3

### Integrations

* DarktraceMBs

### Scripts

* Print

### Commands

* darktrace-get-model-breach
* darktrace-get-model-breach-connections
* darktrace-get-model-breach-comments
* darktrace-post-comment-to-model-breach
* darktrace-acknowledge-model-breach
* closeInvestigation

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---
