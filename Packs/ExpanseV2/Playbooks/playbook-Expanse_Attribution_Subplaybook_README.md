Given an Expanse Asset, Issue IP, Issue Provider, Issue Domain, Issue Port and Issue Protocol hunts for internal activity on the detected service. 
Returns a list of potential owner BUs, owner Users, Device and Notes

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Panorama Query Logs

### Integrations
This playbook does not use any integrations.

### Scripts
* ExpanseAggregateAttributionIP
* ExpanseEnrichAttribution
* ExpanseAggregateAttributionUser
* ExpanseAggregateAttributionDevice

### Commands
* cdl-query-logs
* panorama
* splunk-search
* ad-get-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Asset | Expanse Asset. | ${incident.expanseasset[0]} | Optional |
| IP | Expanse Issue IP. | ${incident.expanseip} | Required |
| Domain | Expanse Issue Domain. | ${incident.expansedomain} | Optional |
| Provider | Expanse Issue Provider. | ${incident.expanseprovider} | Optional |
| Port | Expanse Issue Port. | ${incident.expanseport} | Required |
| Protocol | Expanse Issue Protocol. | ${incident.expanseprotocol} | Required |
| InternalIPRange | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR format, separated by commas. An example of a list of ranges could be: 172.16.0.0/12,10.0.0.0/8,192.168.0.0/16. If a list of IP ranges is not provided, the list provided in the IsIPInRanges script \(the known IPv4 private address ranges\) is used by default. |  | Optional |
| NumberOfDaysInThePast | Number of days to look back to for logs. | 7 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Expanse.AttributionIP | IP addresses | unknown |
| Expanse.AttributionDevice | Devices | unknown |
| Expanse.AttributionUser | Users | Unknown |

## Playbook Image
---
![Expanse Attribution Subplaybook](Insert the link to your image here)