This playbook performs enrichment on different IOC types, and returns the information needed to establish the alert's verdict.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Account Enrichment - Generic v2.1
* AWS IAM - User enrichment
* Domain Enrichment - Generic v2
* Cortex XDR - File Reputation
* URL Enrichment - Generic v2
* IP Enrichment - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* SearchIncidentsV2

### Commands
* wildfire-report
* wildfire-get-verdict

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| threshold | Number of previous alerts that were closed as False Positive alerts before. This will be the threshold to establish whether the Previous Verdict key will be marked as False Positive. | 5 | Optional |
| CloseReason | The closing reason of the previous alerts to search for.<br/>Possible values are:<br/>- Resolved - Threat Handled<br/>- Resolved - True Positive<br/>- Resolved - False Positive<br/>- Resolved - Security Testing<br/>- Resolved - Known Issue<br/>- Resolved - Duplicate Incident<br/>- Resolved - Other<br/>- Resolved - Auto | Resolved - False Positive,Resolved - Duplicate Incident,Resolved - Known Issue | Optional |
| FileMD5 | File MD5 to enrich and give verdict. |  | Optional |
| FileSHA256 | File SHA256 to enrich and give verdict. |  | Optional |
| IP | IP address to enrich and give verdict. |  | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |
| ResolveIP | Determines whether to convert the IP address to a hostname using a DNS query \(True/ False\). |  | Optional |
| URL | URL to enrich and give verdict. |  | Optional |
| User | User to enrich and give verdict. \(AWS IAM or Active Directory\). |  | Optional |
| Domain | Domain to enrich and give verdict. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PreviousVerdict | Suspected verdict for previous alerts. | string |
| VTFileVerdict | Check for VirusTotal verdict. | unknown |
| NSRLFileVerdict | Check for the file presence in NSRL DB. | unknown |
| VTFileSigners | Check VirusTotal if the file is signed by a trusted publisher. | unknown |
| XDRFileSigners | Check XDR Alert if the file is signed by a trusted publisher. | unknown |
| IP | The IP objects | unknown |
| DBotScore | Indicator, Score, Type, Vendor | unknown |
| Endpoint | The Endpoint's object | unknown |
| URL | The URL object. | uknown |
| AWS.IAM.Users | AWS IAM user information. | unknown |
| AWS.IAM.Users.AccessKeys | AWS IAM user access keys information. | unknown |
| Account | The account object. | unknown |
| ActiveDirectory.Users | Active Directory user information. | unknown |
| IPVerdict | Specifies whether the IP addresses were found as suspicious. | unknown |
| URLVerdict | Specifies whether the URLs were found as suspicious. | unknown |
| FileVerdict | Specifies whether the files were found as suspicious. | unknown |
| WildFire.Report | WildFire report object. | unknown |
| WildFire.Report.verdict | The verdict of the report. | unknown |
| WildFire.Verdicts.Verdict | Verdict of the file. | unknown |
| WildFire.Verdicts.VerdictDescription | Description of the file verdict. | unknown |
| DomainVerdict | Domain verdict | unknown |

## Playbook Image
---
![Enrichment for Verdict](https://raw.githubusercontent.com/demisto/content/2d66f3f4c673e252f4f8d44aa944b450b84ee12c/Packs/CommonPlaybooks/doc_files/Enrichment_for_Verdict.png)
