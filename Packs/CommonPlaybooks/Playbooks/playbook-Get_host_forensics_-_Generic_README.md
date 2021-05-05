This playbook purpose is to retrieve forensics from hosts.
The available integration:
- Illusive networks. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Illusive-Collect-Forensics-On-Demand

### Integrations
This playbook does not use any integrations.

### Scripts
* IsIntegrationAvailable

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| fqdn_or_ip | If using illusive integration to retrieve additional forensics please provide fqdn_or_ip of the host that you would like to get the forensics from.  |  | Optional |
| start_date | Date_range must be "number date_range_unit", examples: \(2 hours, 4 minutes,6 months, 1 day, etc.\) |  | Optional |
| end_date | Date_range must be "number date_range_unit", examples: \(2 hours, 4 minutes,6 months, 1 day, etc.\) |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Get host forensics - Generic ](Insert the link to your image here)