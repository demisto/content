Playbook to demonstrate the features of XSOAR-Web-Server. It sends an html email to a set of users up to 2 times. The email can contain multiple html links, that the users can click and the response will be available in the context. This playbook sets up the webserver to handle http get requests


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* xsoar-data-collection-response-tracking

### Integrations
* XSOARWebServer

### Scripts
This playbook does not use any scripts.

### Commands
* setIncident
* stopTimer
* xsoar-ws-setup-simple-action
* getList

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| useremails | The emails to send the data collection links to. | configure the emails | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
