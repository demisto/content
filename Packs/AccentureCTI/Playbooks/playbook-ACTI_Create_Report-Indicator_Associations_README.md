- This sub-playbook makes the connections between ACTI indicators (from ACTI Indicator API) and ACTI intelligence reports (from ACTI Report API) that have pulled into an XSOAR incident via the _**Enrich Incidents with Indicators**_ and _**Enrich Incidents with Intelligence Reports**_ sub-playbooks.
- This sub-playbook _**cannot**_ be integrated into generic XSOAR playbooks and playbooks from other vendors by itself. It is dependent upon the _**Enrich Incidents with Indicators**_ and _**Enrich Incidents with Intelligence Reports**_ sub-playbooks.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* CreateIndicatorRelationship
* GetIndicatorDBotScore
* Exists

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | IP address after enrichment. | ${IP.Address} | Optional |
| IA | Intelligence Alert uuid(s). | ${intelligence_alerts}.None | Optional |
| IR | Intelligence Report uuid(s). | ${intelligence_reports}.None | Optional |
| URL | URL address after enrichment. | ${URL.Data} | Optional |
| Domain | Domain name after enrichment. | ${Domain.Name} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![ACTI Create Report-Indicator Associations](https://user-images.githubusercontent.com/40510780/163230465-e6d61102-93e9-4676-8a8a-30821b58bbba.png)
