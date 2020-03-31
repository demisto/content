Detonates a file in Wildfire and if malicious, pushes its MD5, SHA1 and SHA256 file hashes to McAfee DXL. Example of bridging DXL to a third party sandbox.


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

![Enrich_McAfee_DXL_using_3rd_party_sandbox](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Enrich_McAfee_DXL_using_3rd_party_sandbox.png)
