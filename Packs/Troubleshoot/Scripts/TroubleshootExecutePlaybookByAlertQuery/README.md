Retrieves alerts based on a given query and filter arguments. It provides two operational modes:
 1. Trigger Associated Playbooks: If no specific playbook is provided, the script automatically triggers the playbook that is individually associated with each alert found.
 2. Override Playbook: If a specific playbook ID or name is provided, the script overrides the default playbooks of all matching alerts and uniformly applies the specified playbook to each one.

 This automation requires an API key with Instance Administrator permissions. For further details, refer to the permissions section here:
 https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Permission-Management

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DemistoAPI, troubleshoot |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Core REST API
* core-api-get
* core-api-post

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| query | A query string to filter alerts. For example, to fetch pending alerts, use "runStatus:\\"Pending\\"". |
| playbook_id | The ID of the playbook to apply to the fetched alerts. |
| playbook_name | The name of the playbook to apply to the fetched alerts. |
| limit | The maximum number of alerts to retrieve. |
| incidentTypes | A comma-separated list of alert types to filter the results by. |
| timeField | The field to filter alerts by date range. Options are "created" or "modified". Default is "created". Use "modified" cautiously due to performance limitations. |
| fromDate | The start date for filtering alerts. Accepted formats are similar to those on the alerts query page \(e.g., "3 days ago" or "2019-01-01T00:00:00 \+0200"\). |
| toDate | The end date for filtering alerts. Accepted formats are similar to those on the alerts query page \(e.g., "3 days ago" or "2019-01-01T00:00:00 \+0200"\). |
| NonEmptyFields | A comma-separated list of alert field names that must have non-empty values for the alert to be included. |
| populateFields | A comma-separated list of object fields to populate in the results. |
| pageSize | Alerts query batch size. |
| reopen_closed_inv | If set to true, the script will reopen any closed investigations to execute the pending playbook on the matching alerts. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ReopenedAlerts.IDs | Alerts that have been reopened. | list |
