This playbook accepts an XDR endpoint ID and isolates it using the 'Palo Alto Networks Cortex XDR - Investigation and Response' integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
GenericPolling

### Integrations
CortexXDRIR

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-get-endpoints
* xdr-isolate-endpoint

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_id | The endpoint ID \(string\) to isolate. You can retrieve the ID using the xdr-get-endpoints command. | PaloAltoNetworksXDR.Endpoint.endpoint_id | Optional |
| hostname | A comma-separated list of hostnames. | Endpoint.Hostname | Optional |
| ip_list | A comma-separated list of IP addresses. | IP.Address | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Endpoint.endpoint_id | The endpoint ID. | unknown |
| PaloAltoNetworksXDR.Endpoint.endpoint_name | The endpoint name. | unknown |
| PaloAltoNetworksXDR.Endpoint.endpoint_status | The status of the endpoint. | unknown |
| PaloAltoNetworksXDR.Endpoint.ip | A list of IP addresses. | unknown |
| PaloAltoNetworksXDR.Endpoint.is_isolated | Whether the endpoint is isolated. | unknown |
| Endpoint.Hostname | The hostname that is mapped to this endpoint. | unknown |

## Playbook Image
---
![Cortex XDR - Isolate Endpoint](https://github.com/demisto/content/raw/ee07059dc8769d6f5652a4a07b668d63266cafaf/Packs/CortexXDR/doc_files/Cortex_XDR_-_Isolate_Endpoint.png)
