DEPRECATED. Use "Enrich McAfee DXL using 3rd party sandbox v2" playbook instead. Detonates a file in Wildfire and if malicious, pushes its MD5, SHA1 and SHA256 file hashes to McAfee DXL. Example of bridging DXL to a third party sandbox.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* McAfee DXL

### Scripts
* CloseInvestigation
* Exists

### Commands
* dxl-send-event

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Enrich_McAfee_DXL_using_3rd_party_sandbox](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Enrich_McAfee_DXL_using_3rd_party_sandbox.png)
