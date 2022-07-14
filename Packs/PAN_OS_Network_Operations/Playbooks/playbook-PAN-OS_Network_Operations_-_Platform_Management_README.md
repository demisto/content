Retrieves all the details of the PAN-OS Platform and topology.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Network Operations - Incident Callback
* Update Occurred Time

### Integrations
This playbook does not use any integrations.

### Scripts
* DeleteContext
* CreateOrUpdateDeviceIncident
* Sleep

### Commands
* pan-os-platform-get-system-info
* pan-os-platform-get-global-counters
* pan-os-platform-get-bgp-peers
* pan-os-platform-get-route-summary
* setIncident
* pan-os-platform-get-routes
* pan-os-platform-get-arp-tables

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| close_task_id | If set, completes the given task in the parent playbook. Used to ensure that the parent does not continue until this incident is finished processing. |  | Optional |
| parent_incident_id | Incident that initiated this subplaybook, if any. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PANOS.ShowSystemInfo.Result | PANOS System Information | unknown |
| PANOS.ShowArp.Result | PANOS ARP Table Details | unknown |
| PANOS.ShowRouteSummary.Summary | PANOS Route table summary | unknown |
| PANOS.ShowCounters.Result | PANOS Global counters | unknown |

## Playbook Image
---
![PAN-OS Network Operations - Platform Management](../doc_files/PAN-OS_Network_Operations_-_Platform_Management.png)