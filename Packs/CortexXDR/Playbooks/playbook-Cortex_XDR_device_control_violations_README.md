Queries Cortex XDR for device control violations for the specified hosts, IP address, or XDR endpoint ID. It then communicates via email with the involved users to understand the nature of the incident and if the user connected the device. 
All the collected data will be displayed in the XDR device control incident layout.
This playbook can also be associated with Cortex XDR device control violation job to periodically query and investigate XDR device control violations. In this configuration, the playbook will only communicate with the involved users.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CortexXDRIR
* Active Directory Query v2

### Scripts
This playbook does not use any scripts.

### Commands
* ad-get-user
* xdr-get-endpoint-device-control-violations

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TimeStamp | Timestamp in relative date format for query device control events from Cortex XDR. |  | Optional |
| EndpointID | XDR endpoint ID to filter results for. |  | Optional |
| Hostname | Hostname to filter results for. |  | Optional |
| IPAddress | IP address to filter results for. |  | Optional |
| MessageSubject | The subject of the message for communication with the involved users. | Device control violation | Optional |
| MessageBody | The body of the message for communication with the involved users. | Hello,<br/>Your user was involved with a device control violation. Please open the following link to fill in the needed information to understand the incident further. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR device control violations](Insert the link to your image here)
