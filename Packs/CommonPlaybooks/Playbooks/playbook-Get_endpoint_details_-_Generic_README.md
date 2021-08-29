This playbook uses the generic command !endpoint to retrieve details on a specific endpoint.
This command currently supports the following integrations:
- Palo Alto Networks Cortex XDR - Investigation and Response.
- CrowdStrike Falcon. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
Set

### Commands
endpoint

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_id | The ID of the endpoint that you want to get details about.  |  | Optional |
| Endpoint_ip | The IP of the endpoint that you want to get details about.  |  | Optional |
| Endpoint_hostname | The hostname of the endpoint that you want to get details about.  |  | Optional |

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
| Endpoint.Vendor | The integration name of the endpoint vendor. | string |

## Playbook Image
---
![Get endpoint details - Generic](https://raw.githubusercontent.com/demisto/content/7138d5c3ca780a7d385623aff3f63f113845c36b/Packs/CommonPlaybooks/doc_files/Get_endpoint_details_-_Generic.png)
