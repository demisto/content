Retrieves extra data fields of a specific case including issues and key artifacts.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.6.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Cortex Core - Platform
* core-get-case-extra-data

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| case_id | An array or CSV string of case IDs. |
| issues_limit | Maximum number of issues to return per case. The default and maximum is 1000. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.CaseExtraData.case_id | The unique identifier for the case. | String |
| Core.CaseExtraData.case_name | The name assigned to the case. | String |
| Core.CaseExtraData.creation_time | The timestamp \(in epoch format\) when the case was created. | Number |
| Core.CaseExtraData.modification_time | The timestamp \(in epoch format\) when the case was last modified. | Number |
| Core.CaseExtraData.detection_time | The timestamp when the activity related to the case was first detected. | String |
| Core.CaseExtraData.status | The current status of the case \(e.g., 'new', 'under_investigation', 'closed'\). | String |
| Core.CaseExtraData.severity | The severity level of the case \(e.g., 'low', 'medium', 'high', 'critical'\). | String |
| Core.CaseExtraData.description | A detailed textual description of the case. | String |
| Core.CaseExtraData.assigned_user_mail | The email address of the user assigned to the case. | String |
| Core.CaseExtraData.assigned_user_pretty_name | The display name of the user assigned to the case. | String |
| Core.CaseExtraData.issue_count | The total number of issues associated with the case. | Number |
| Core.CaseExtraData.low_severity_issue_count | The total number of low-severity issues within the case. | Number |
| Core.CaseExtraData.med_severity_issue_count | The total number of medium-severity issues within the case. | Number |
| Core.CaseExtraData.high_severity_issue_count | The total number of high-severity issues within the case. | Number |
| Core.CaseExtraData.critical_severity_issue_count | The total number of critical-severity issues within the case. | Number |
| Core.CaseExtraData.user_count | The number of unique users involved in the case. | Number |
| Core.CaseExtraData.host_count | The number of unique hosts involved in the case. | Number |
| Core.CaseExtraData.notes | A collection of notes or comments added to the case by analysts. | Array |
| Core.CaseExtraData.resolve_comment | The comment entered by a user when resolving the case. | String |
| Core.CaseExtraData.manual_severity | The severity level manually set by a user, which may override the calculated severity for the case. | String |
| Core.CaseExtraData.manual_description | A description of the case that was manually entered by a user. | String |
| Core.CaseExtraData.xdr_url | The direct URL to view the case in the XDR platform. | String |
| Core.CaseExtraData.starred | A flag indicating whether the case has been starred or marked as a favorite. | Boolean |
| Core.CaseExtraData.hosts | A comma-separated list of hostnames involved in the case. | Array |
| Core.CaseExtraData.case_sources | The products or sources that contributed issues to this case \(e.g., 'XDR Agent', 'Firewall'\). | String |
| Core.CaseExtraData.rule_based_score | The case's risk score as calculated by automated detection rules. | Number |
| Core.CaseExtraData.manual_score | A risk score manually assigned to the case by a user. | Number |
| Core.CaseExtraData.wildfire_hits | The number of times a file associated with this case was identified as malicious by WildFire. | Number |
| Core.CaseExtraData.issues_grouping_status | The current status of the issue grouping or clustering process for this case. | String |
| Core.CaseExtraData.mitre_techniques_ids_and_names | A list of MITRE ATT&amp;CK technique IDs and names observed in the case. | Array |
| Core.CaseExtraData.mitre_tactics_ids_and_names | A list of MITRE ATT&amp;CK tactic IDs and names observed in the case. | Array |
| Core.CaseExtraData.issue_categories | A comma-separated list of categories for the issues included in the case. | String |
| Core.CaseExtraData.issue_ids | Ids of related issues. | Array |
| Core.CaseExtraData.network_artifacts.total_count | The total number of network artifacts associated with the case. | Number |
| Core.CaseExtraData.network_artifacts.data.type | The type of network artifact \(e.g., 'IP Address', 'Domain'\). | String |
| Core.CaseExtraData.network_artifacts.data.issue_count | The number of issues in the case that involve this network artifact. | Number |
| Core.CaseExtraData.network_artifacts.data.is_manual | A flag indicating if the network artifact was added manually by a user. | Boolean |
| Core.CaseExtraData.network_artifacts.data.network_domain | The domain name of the network artifact. | String |
| Core.CaseExtraData.network_artifacts.data.network_remote_ip | The remote IP address of the network artifact. | String |
| Core.CaseExtraData.network_artifacts.data.network_remote_port | The remote port number of the network artifact. | String |
| Core.CaseExtraData.network_artifacts.data.network_country | The country associated with the network artifact's IP address. | String |
| Core.CaseExtraData.file_artifacts.total_count | The total number of file artifacts associated with the case. | Number |
| Core.CaseExtraData.file_artifacts.data.issue_count | The number of issues in the case that involve this file artifact. | Number |
| Core.CaseExtraData.file_artifacts.data.file_name | The name of the file artifact. | String |
| Core.CaseExtraData.file_artifacts.data.File_sha256 | The SHA256 hash of the file artifact. | String |
| Core.CaseExtraData.file_artifacts.data.file_signature_status | The digital signature status of the file artifact. | String |
| Core.CaseExtraData.file_artifacts.data.file_wildfire_verdict | The verdict from WildFire for this file \(e.g., 'malicious', 'benign'\). | String |
| Core.CaseExtraData.file_artifacts.data.is_malicous | A flag indicating whether the file artifact is considered malicious. | Boolean |
| Core.CaseExtraData.file_artifacts.data.is_manual | A flag indicating if the file artifact was added manually by a user. | Boolean |
| Core.CaseExtraData.file_artifacts.data.is_process | A flag indicating if the file artifact is a process executable. | Boolean |
| Core.CaseExtraData.file_artifacts.data.low_confidence | A flag indicating if the verdict on the file artifact has low confidence. | Boolean |
| Core.CaseExtraData.file_artifacts.data.type | The type of the file artifact. | String |
