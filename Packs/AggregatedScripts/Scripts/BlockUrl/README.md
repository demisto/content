The script blocks a list of URLs in supported integrations.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.1.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Panorama
* pan-os
* pan-os-apply-security-profile
* pan-os-commit
* pan-os-commit-status
* pan-os-create-rule
* pan-os-create-tag
* pan-os-edit-custom-url-category
* pan-os-get-custom-url-category
* pan-os-get-url-filter
* pan-os-list-rules
* pan-os-move-rule
* pan-os-push-status
* pan-os-push-to-device-group

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| url_list | List of URLs to block. The scheme is stripped before the URL is submitted to the firewall. |
| brands | Which integrations brands to run the command for. If not provided, the command will run for all available integrations.<br/>For multi-select provide a comma-separated list. The possible values are: Panorama. |
| rule_name | The name of the security rule which will be created in the relevant products. |
| url_category | The name of the PAN-OS custom URL category which holds the blocked URLs. |
| url_filtering_profile | The name of the PAN-OS URL Filtering security profile which blocks the custom URL category. |
| log_forwarding_name | Panorama log forwarding object name. Indicates what type of Log Forwarding setting will be specified in the PAN-OS custom rules. |
| tag | The designated tag name for the objects the script creates. |
| auto_commit | Whether to commit the new rule. |
| verbose | Whether to retrieve a human-readable entry for every command or only the final result. True retrieves a human-readable entry for every command. False retrieves a human-readable entry only for the final result. |
| commit_job_id | Commit job ID to use in polling commands. \(automatically filled by polling\). |
| push_job_id | Push job ID to use in polling commands. \(automatically filled by polling\). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BlockURLResults.URL | The URL that was requested to be blocked, as it was supplied. | String |
| BlockURLResults.SubmittedURL | The normalized URL that was submitted to the brand. Empty when the URL was rejected before submission. | String |
| BlockURLResults.Brand | The name of the brand that was executed. | String |
| BlockURLResults.Result | The result of the action, Success, Failed or Skipped. | String |
| BlockURLResults.Message | A message concerning the result of the action. | String |
| BlockURLResults.RuleName | The name of the security rule that blocks the URL. | String |
| BlockURLResults.URLCategory | The name of the custom URL category that holds the URL. | String |
| BlockURLResults.JobID | The ID of the PAN-OS commit job. | String |
