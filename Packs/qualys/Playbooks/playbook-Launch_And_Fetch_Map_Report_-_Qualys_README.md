Launches a map scan report and fetches the report when it's ready.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
GenericPolling

### Integrations
QualysV2

### Scripts
This playbook does not use any scripts.

### Commands
* qualys-report-launch-map
* qualys-report-fetch

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| template_id | The template ID of the report you want to launch. Can be found by running the command qualys-report-template-list. |  | Required |
| output_format | One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. |  | Required |
| report_refs | Specifies the map references \(1 or 2\) to include. A map reference starts with the string "map/" followed by a reference ID number. When two map references are given, the report compares map results. Two map references are comma separated. |  | Required |
| report_title | A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed. |  | Optional |
| hide_header | \(Valid for CSV format report only\). Specify hide_header=1 to omit the header information from the report. By default this information is included. |  | Optional |
| recipient_group_id | The report recipients in the form of one or more distribution group IDs. Multiple distribution group IDs are comma separated. Where do I find this ID? Log in to your Qualys account, go to Users &amp;gt; Distribution Groups and select Info for a group in the list. |  | Optional |
| pdf_password | \(Required for secure PDF distribution, Manager or Unit Manager only\) Used for secure PDF report distribution when this feature is enabled in the user's account \(under Reports &amp;gt; Setup &amp;gt; Report Share\). The password to be used for encryption. Requirements: <br>- The password must have a minimum of 8 characters \(ascii\), and a maximum of 32 characters <br>- The password must contain alpha and numeric characters <br>- The password cannot match the password for the user’s Qualys account. <br>- The password must follow the password security guidelines defined for your subscription \(under Users &amp;gt; Setup &amp;gt; Security\) |  | Optional |
| recipient_group | Used for secure PDF distribution. The report recipients in the form of one or more distribution group names, as defined using the Qualys UI. Multiple distribution groups are comma separated. A maximum of 50 distribution groups may be entered. |  | Optional |
| ip_restriction | For a map report, specifies certain IPs/ranges to include in the report. Multiple IPs and/or ranges are comma separated. |  | Optional |
| domain | Specifies the target domain for the map report. Include the domain name only; do not enter "www." at the start of the domain name. When the special “none” domain is specified as a parameter value, the ip_restriction parameter is required. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Launch And Fetch Map Report - Qualys](../doc_files/Launch_And_Fetch_Map_Report_-_Qualys.png)
