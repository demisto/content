Use this job to collect Cortex XDR incident data and store it into a related XSOAR list for the use of Cortex XDR dashboard widgets.

- To configure the job correctly:
- Create a new recurring job.
- Configure the recurring schedule(Every 10 minutes is recommended).
- Add a name.
- Configure this playbook as the job playbook.

Job configuration and detailed information 
https://xsoar.pan.dev/docs/incidents/incident-jobs


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* XDRCreateDashboardData

### Commands
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Job - Cortex XDR dashboard](https://raw.githubusercontent.com/demisto/content/4123f22947b742a3dfe63e4be0f6cfefb60cab23/Packs/CortexXDR/doc_files/Job_-_Cortex_XDR_dashboard.png)