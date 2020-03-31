Compares incidents in Palo Alto Networks Cortex XDR and Demisto, and updates the incidents appropriately. When an incident is updated in Demisto, the XDRSyncScript will update the incident in XDR. When an incident is updated in XDR, the XDRSyncScript will update the incident fields in Demisto and rerun the current playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
* XDRSyncScript
* StopScheduledTask

### Commands
* closeInvestigation
* xdr-update-incident

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

![PaloAltoNetworks_Cortex_XDR_Incident_Sync](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Cortex_XDR_Incident_Sync.png)
