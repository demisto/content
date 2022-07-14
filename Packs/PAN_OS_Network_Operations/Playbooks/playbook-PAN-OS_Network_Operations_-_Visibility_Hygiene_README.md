Check the PANOS Platform for configuration hygiene issues, such as misconfigured profiles, zones, and log forwarding.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Network Operations - BPA Wrapper
* Update Occurred Time

### Integrations
This playbook does not use any integrations.

### Scripts
* DeleteContext

### Commands
* pan-os-hygiene-check-url-filtering-profiles
* linkIncidents
* pan-os-hygiene-check-vulnerability-profiles
* pan-os-hygiene-check-log-forwarding
* pan-os-hygiene-check-security-rules
* pan-os-hygiene-check-spyware-profiles
* setIncident
* pan-os-hygiene-check-security-zones

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| target | Target Device | ${incident.panosnetworkoperationstarget} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Visibility Hygiene](../doc_files/PAN-OS_Network_Operations_-_Visibility_Hygiene.png)