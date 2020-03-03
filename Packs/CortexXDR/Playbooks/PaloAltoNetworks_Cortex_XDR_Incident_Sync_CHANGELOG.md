## [Unreleased]


## [19.11.0] - 2019-11-12
#### New Playbook
Compares incidents in Palo Alto Networks Cortex XDR and Demisto, and updates the incidents appropriately. When an incident is updated in Demisto, the XDRSyncScript will update the incident in XDR. When an incident is updated in XDR, the XDRSyncScript will update the incident fields in Demisto and rerun the current playbook.