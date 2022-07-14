Similar to the Platform Upgrade playbook, this playbook uses an alternate method of retrieving the devices to upgrade by instead querying the open device incidents for the information. This allows us to create upgrade incidents for only specific devices or groups of devices as opposed to all devices.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Network Operations - Start Device Upgrades

### Integrations
This playbook does not use any integrations.

### Scripts
* GetDevicesByQuery
* Set
* FilterAvailableSoftwareImages
* DeleteContext
* PrintErrorEntry

### Commands
* createNewIncident
* pan-os-platform-get-available-software
* setIncident
* linkIncidents
* pan-os-platform-get-system-info
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| upgrade_domain | Administrative domain - will search the "Device Administrative Domain" tag field in device incidents for this group. | ${incident.panosnetworkoperationsdeviceadministrativedomain} | Optional |
| device_query | Any additional incident query parameters for the device query - for example, use "devicemodel:Panorama" to only upgrade Panorama devices.  | ${incident.panosnetworkoperationsdeviceupgradequery} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Domain Upgrade](../doc_files/PAN-OS_Network_Operations_-_Domain_Upgrade.png)