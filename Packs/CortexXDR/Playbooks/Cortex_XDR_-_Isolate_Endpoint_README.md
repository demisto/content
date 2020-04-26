This playbook accepts an XDR endpoint ID and isolates it using the 'Palo Alto Networks Cortex XDR - Investigation and Response' integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-isolate-endpoint
* xdr-get-endpoints

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| endpoint_id | The endpoint ID \(string\) to isolate. You can retrieve the ID using the xdr\-get\-endpoints command. | Endpoint.endpoint_id | PaloAltoNetworksXDR | Optional |
| hostname | A comma\-separated list of hostnames. | Hostname | Endpoint | Optional |
| ip_list | A comma\-separated list of IP addresses. | Address | IP | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->