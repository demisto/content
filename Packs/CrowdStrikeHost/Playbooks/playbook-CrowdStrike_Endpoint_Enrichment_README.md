Enriches Endpoints with CrowdStrike.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
This playbook does not use any integrations.

## Scripts
This playbook does not use any scripts.

## Commands
* cs-device-search
* cs-device-details

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname to enrich. | ${Endpoint.Hostname} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.ID | The unique ID of the endpoint in FalconHost. | string |
| Endpoint.IPAddress | The IP address of the endpoint. | string |
| Endpoint.Domain | The domain of the endpoint. | string |
| Endpoint.MACAddress | The MAC address of the endpoint. | string |
| Endpoint.OS | The OS of the endpoint. | string |
| Endpoint.OSVersion | The OS version of the endpoint. | string |
| Endpoint.BIOSVersion | The BIOS version of the endpoint. | string |
| Endpoint.HostName | The host of the endpoint. | string |

## Playbook Image
---
![CrowdStrike_Endpoint_Enrichment](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/CrowdStrike_Endpoint_Enrichment.png)
