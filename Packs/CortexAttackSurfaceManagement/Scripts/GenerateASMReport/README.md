Generate an ASM Alert Summary report.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| alert_id | Numerical ID of the ASM alert. |
| alert_name | Name of the alert that triggered this playbook. |
| alert_details | Details of the alert that triggered this playbook. |
| alert_severityStr | ASM alert severity string. |
| asm_service_owner | Potential service owners gathered through the playbook. |
| asm_remediation | Collect information on remediation action\(s\). |
| asm_service_detection | Pre/Post remediation scan to check if the service is still detectable. |
| asm_system_ids | Related system identifiers. |
| asm_cloud | Information on cloud assets. |
| asm_notification | Information on notification\(s\) sent via the ASM playbook. |
| asm_data_collection | Collect information on data collection tasks. |
| asm_tags | Tags from objects that can be used to determine other information \(if server is Dev for example\). |
| asm_private_ip | Private IP addresses found. |
| asm_related | Related or duplicate objects. |
| asm_remediation_path_rule | Matched remediation path rule \(if there is a match\). |
| asm_service_id | External Service ID for generating Service Summary. |
| asm_asset_id | Asset ID related to alert. |
| report_type | Type of report to generate \(Analysis report after enrichment or Summary). |

## Outputs

---
There are no outputs for this script.
