This playbook use the generic command !endpoint to retrieve details on specific endpoint.
This command currently supporting the next integration:
- Palo Alto Networks Cortex XDR - Investigation and Response.
- CrowdStrike Falcon. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* endpoint

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_id | The id of the endpoint that you wish get details on.  |  | Optional |
| Endpoint_ip | The IP of the endpoint that you wish get details on.  |  | Optional |
| Endpoint_hostname | The hostname of the endpoint that you wish get details on.  |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.Hostname | The endpoint's hostname. | string |
| Endpoint.OS | The endpoint's operation system. | string |
| Endpoint.IPAddress | The endpoint's IP address. | string |
| Endpoint.ID | The endpoint's ID. | string |
| Endpoint.Status | The endpoint's status. | string |
| Endpoint.IsIsolated | Endpoint isolation status. | string |
| Endpoint.MACAddress | Endpoint MAC Address. | string |
| Endpoint.Vendor | Endpoint Vendor, the integration name. | string |

## Playbook Image
---
![Get endpoint details - Generic](https://github.com/demisto/content/raw/ee07059dc8769d6f5652a4a07b668d63266cafaf/Packs/CommonPlaybooks/doc_files/Get_endpoint_details_-_Generic.png)