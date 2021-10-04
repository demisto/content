This playbook retrieves forensics from hosts.
The available integration is Illusive networks. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Illusive-Collect-Forensics-On-Demand

### Integrations
This playbook does not use any integrations.

### Scripts
IsIntegrationAvailable

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| fqdn_or_ip | If using illusive integration to retrieve additional forensics, provide fqdn_or_ip of the host from which to get the forensics.  |  | Optional |
| start_date | Date_range must be "number date_range_unit", examples: \(2 hours, 4 minutes,6 months, 1 day, etc.\) |  | Optional |
| end_date | Date_range must be "number date_range_unit", examples: \(2 hours, 4 minutes,6 months, 1 day, etc.\) |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Get host forensics - Generic ](https://raw.githubusercontent.com/demisto/content/6fc775d242aab0ca7adfff77073d63614e8c1933/Packs/CommonPlaybooks/doc_files/Get_host_forensics_-_Generic.png)
