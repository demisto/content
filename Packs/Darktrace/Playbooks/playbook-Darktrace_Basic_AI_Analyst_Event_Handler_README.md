Handles each fetched Darktrace AI Analyst Event by gathering additional detail about the activity through enrichment data from Darktrace and XSOAR. Additionally, it offers the ability to take proactive actions from XSOAR to your Darktrace deployment.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Entity Enrichment - Generic v3

### Integrations

* DarktraceAIA

### Scripts

* Print

### Commands

* darktrace-get-ai-analyst-incident-event
* darktrace-post-tag-to-device
* darktrace-get-model-breach
* darktrace-get-ai-analyst-incident-group-from-eventId
* darktrace-acknowledge-ai-analyst-incident-event
* closeInvestigation

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---
