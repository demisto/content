Upgrades a single or HA pair of PAN-OS firewalls.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Network Operations - Single Device Upgrade

### Integrations
This playbook does not use any integrations.

### Scripts
* Sleep
* PrintErrorEntry
* Set
* DeleteContext

### Commands
* pan-os-platform-update-ha-state
* createNewIncident
* pan-os-platform-get-system-status
* setIncident
* pan-os-platform-get-ha-state
* taskComplete
* linkIncidents
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| target_device | Target Firewall for upgrade | ${incident.panosnetworkoperationsupgradetargetdevice} | Optional |
| peer_device | Peer firewall \(if any\) | ${incident.panosnetworkoperationsupgradepeerfirewall} | Optional |
| target_version | Target version of upgrade | ${incident.panosnetworkoperationsupgradetargetversion} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Device Upgrade](../doc_files/PAN-OS_Network_Operations_-_Device_Upgrade.png)