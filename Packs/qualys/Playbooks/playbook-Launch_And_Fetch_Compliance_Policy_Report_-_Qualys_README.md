Launches a compliance policy report and then fetches the report when it's ready.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
GenericPolling

### Integrations
QualysV2

### Scripts
This playbook does not use any scripts.

### Commands
* qualys-report-launch-compliance-policy
* qualys-report-fetch

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| template_id | The template ID of the report you want to launch. Can be found by running the qualys-report-template-list command. |  | Required |
| output_format | One output format can be specified. When output_format=pdf is specified, the Secure PDF Distribution can be used. |  | Required |
| report_title | A user-defined report title. The title can have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed. |  | Optional |
| hide_header | \(Valid for CSV format report only\). Specify hide_header=1 to omit the header information from the report. By default, this information is included. |  | Optional |
| recipient_group_id | Specify users who will receive the email notification when the report is complete \(i.e., supply a distribution group ID\). Where do I find this ID? Log in to your Qualys account, go to Users &amp;gt; Distribution Groups and select Info for a group in the list. |  | Optional |
| pdf_password | \(Required for secure PDF distribution, Manager or Unit Manager only\) Used for secure PDF report distribution when this feature is enabled in the user's account \(under Reports &amp;gt; Setup &amp;gt; Report Share\). The password to be used for encryption. <br/>- The password must have a minimum of 8 characters \(ascii\), and a maximum of 32 characters. <br/>- The password must contain alpha and numeric characters. <br/>- The password cannot match the password for the user’s Qualys account. <br/>- The password must follow the password security guidelines defined for your subscription \(under Users &amp;gt; Setup &amp;gt; Security\) |  | Optional |
| recipient_group | Used for secure PDF distribution. The report recipients in the form of one or more distribution group names, as defined using the Qualys UI. Multiple distribution groups are comma separated. A maximum of 50 distribution groups may be entered. |  | Optional |
| ips | \(Optional for compliance report\) For a compliance report \(except a PCI report\), specify the IPs/ranges you want to include in the report. Multiple IPs and/or ranges are comma separated. |  | Optional |
| asset_group_ids | \(Optional for compliance report\) For a compliance report \(except a PCI report\), specify asset groups IDs which identify hosts to include in the report. Multiple asset group IDs are comma separated. Looking for asset group IDs? Use the asset_group_list.php function \(in the API v1 User Guide\). |  | Optional |
| policy_id | Specifies the policy to run the report on. A valid policy ID must be entered. |  | Required |
| host_id | In the policy report output, show only results for a single host instance. Specify the ID for the host to include in the report. A valid host ID must be entered. |  | Optional |
| instance_string | Specifies a single instance on the selected host. The instance string may be “os” or a string like “oracle10:1:1521:ora10204u”. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Launch And Fetch Compliance Policy Report - Qualys](../doc_files/Launch_And_Fetch_Compliance_Policy_Report_-_Qualys.png)
