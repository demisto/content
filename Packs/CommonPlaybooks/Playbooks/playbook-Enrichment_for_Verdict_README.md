This playbook checks prior alert closing reasons and performs enrichment on different IOC types. It then  returns the information needed to establish the alert's verdict.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Domain Enrichment - Generic v2
* File Reputation
* URL Enrichment - Generic v2
* IP Enrichment - Generic v2
* Account Enrichment - Generic v2.1
* AWS IAM - User enrichment

### Integrations
This playbook does not use any integrations.

### Scripts
* IsIntegrationAvailable
* Set
* SearchIncidentsV2

### Commands
* wildfire-report
* wildfire-get-verdict

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| threshold | The number of previous alerts that were closed as false positive alerts. This threshold establishes whether the Previous Verdict key will be marked as false positive. | 5 | Optional |
| query | A query for the previous alerts search.<br/>Use free form query \(Lucene syntax\) as a filter. All other filters are ignored when this filter is used. | (initiatorsha256:${inputs.FileSHA256} or hostip:${inputs.IP}) and alertsource:${alert.sourceBrand} and alertname:${alert.name} | Optional |
| CloseReason | The closing reason of the previous alerts to search for.<br/>Possible values are:<br/>- Resolved - Threat Handled<br/>- Resolved - True Positive<br/>- Resolved - False Positive<br/>- Resolved - Security Testing<br/>- Resolved - Known Issue<br/>- Resolved - Duplicate Incident<br/>- Resolved - Other<br/>- Resolved - Auto | Resolved - False Positive,Resolved - Duplicate Incident,Resolved - Known Issue | Optional |
| FileMD5 | File MD5 to enrich and give verdict. |  | Optional |
| FileSHA256 | File SHA256 to enrich and give verdict. | alert.initiatorsha256 | Optional |
| IP | IP address to enrich and give verdict. | alert.hostip | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges is: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use the default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |
| ResolveIP | Determines whether to convert the IP address to a hostname using a DNS query \(True/ False\). |  | Optional |
| URL | URL to enrich and give verdict. | alert.url | Optional |
| User | User to enrich and give verdict. \(AWS IAM or Active Directory\). | alert.username | Optional |
| Domain | Domain to enrich and give verdict. | alert.domainname | Optional |
| awsUser | Name of the AWS IAM user to enrich. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PreviousVerdict | Suspected verdict for previous alerts. | string |
| VTFileVerdict | Check for VirusTotal verdict. | unknown |
| NSRLFileVerdict | Check for the file presence in NSRL DB. | unknown |
| VTFileSigners | Check VirusTotal if the file is signed by a trusted publisher. | unknown |
| XDRFileSigners | Check XDR alert if the file is signed by a trusted publisher. | unknown |
| IP | The IP objects. | unknown |
| DBotScore | Indicator's dbot Score, dbot Type and Vendor. | unknown |
| Endpoint | The endpoint's object. | unknown |
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
![Enrichment for Verdict](https://raw.githubusercontent.com/demisto/content/83139fce8bb3f76917669e780df144115da69c90/Packs/CommonPlaybooks/doc_files/Enrichment_for_Verdict.png)