Queries QRadar SIEM for indicators such as file hashes, IP addresses, domains, or URLs. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* QRadarFullSearch

### Integrations
This playbook does not use any integrations.

### Scripts
* IsIPInRanges
* Set
* SetAndHandleEmpty

### Commands
* qradar-get-assets

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| MD5 | The MD5 hash or an array of hashes to search. | - | Optional |
| QradarMD5Field | The MD5 hash field to search in QRadar. If none are specified, the search will use a payload contains filter. | - | Optional |
| SHA1 | The SHA1 hash or an array of hashes to search. | - | Optional |
| QradarSHA1Field | The SHA1 hash field to search in QRadar. If none are specified, the search will use a payload contains filter. | - |  Optional |
| SHA256 | The SHA256 hash or an array of hashes to search. | - | Optional |
| QradarSHA256Field | The SHA256 hash field to search in QRadar. If none are specified, the search will use a payload contains filter. | - | Optional |
| IPAddress | The source or destination IP address to search. Can be a single address or an array of addresses. | - | Optional |
| QradarIPfield | The IP address field to search in QRadar. If none are specified, the search will use `sourceip` or `destinationip` (combined). | sourceip,destinationip | Optional |
| URLDomain | Domain or URL can be single or an array of domain/URLs to search. By default the **LIKE** clause is used. | - | Optional |
| QradarURLDomainField | URL/Domain field to search in QRadar. If none are specified, the search will use a payload contains filter.  | - | Optional |
| TimeFrame | Time frame as used in AQL. For example, "LAST 7 DAYS", "START '2019-09-25 15:51' STOP '2019-09-25 17:51'". For more examples review IBM's AQL documentation. | LAST 7 DAYS | Optional |
| InternalRange | A list of internal IP address ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" (without quotes). If a list is not provided, will use default list provided in the `IsIPInRanges` script (the known IPv4 private address ranges). | - | Optional |
| InvestigationIPFields | The values of these QRadar fields will be used for the playbook IP addresses outputs. | sourceip,destinationip | Required |
| InvestigationUserFields | The values of these QRadar fields will be used for the playbook user name outputs. | username | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QRadar.DetectedUsers | The users detected based on the username field in your search. | string |
| QRadar.DetectedInternalIPs | The internal IP addresses detected based on fields and inputs in your search. | string |
| QRadar.DetectedExternalIPs | The external IP addresses detected based on fields and inputs in your search. | string |
| QRadar.DetectedInternalHosts | The internal host names detected based on hosts in your assets table. Note that the data accuracy depends on how the asset mapping is configured in QRadar. | string |
| QRadar.DetectedExternalHosts | The external host names detected based on hosts in your assets table. Note that the data accuracy depends on how the asset mapping is configured in QRadar. | string |

## Playbook Image
---
![QRadar_Indicator_Hunting_V2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/QRadar_Indicator_Hunting_V2.png)
