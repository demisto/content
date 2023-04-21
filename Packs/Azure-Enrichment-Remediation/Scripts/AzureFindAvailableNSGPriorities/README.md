This script takes in a list of numbers that represent Azure priorities for NSG rules, a target priority number, and a number available priorities to return available priorities from the provided list. 

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Used In

---
This script is used in the following playbooks and scripts.
- Azure - Network Security Group Remediation

## Inputs

---

| **Argument Name** | **Description** | **Mandatory** |
| --- | --- | --- |
| target_rule_priority | The NSG priority to start finding available priorities from. The target priority cannot be 100. | True |
| number_of_available_priorities_to_retrieve | The number of priorities that are available to be returned. \(limit: 5\) | True |
| list_of_priorities_from_rules | The list of priorities from rules in an Azure Network Security Group. \(limit: 995\) | True |

## Outputs

---

| **Context Path** | **Description** | **Type** |
| --- | --- | --- |
| AvailableAzureNSGPriorities | List of numbers that represent available Azure NSG priorities | Unknown |
