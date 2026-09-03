Looks up a URL's categorization/reputation info via ***netskopev2-url-lookup*** and records the result as labels directly on the incident.

netskopev2-url-lookup is a licensed feature on the Netskope side - if you get an error mentioning licensing/enablement, URL Lookup needs to be enabled for your tenant by Netskope support.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Netskope - Direct to Zero Trust

### Scripts

* NetskopeURLLookupLabels

### Commands

* netskopev2-url-lookup
* setIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | The URL to look up. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.
