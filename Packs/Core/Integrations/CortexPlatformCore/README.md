This integration uses the Cortex API to access all the core services and capabilities of the Cortex platform.

## Configure Cortex Platform Core in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| HTTP Timeout | The timeout of the HTTP requests sent to Cortex API \(in seconds\). | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### core-get-asset-details

***
Get asset information.

#### Base Command

`core-get-asset-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset unique identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.CoreAsset | unknown | Asset additional information. |
| Core.CoreAsset.xdm__asset__provider | unknown | The cloud provider or source responsible for the asset. |
| Core.CoreAsset.xdm__asset__realm | unknown | The realm or logical grouping of the asset. |
| Core.CoreAsset.xdm__asset__last_observed | unknown | The timestamp when the asset was last observed, in ISO 8601 format. |
| Core.CoreAsset.xdm__asset__type__id | unknown | The unique identifier for the asset type. |
| Core.CoreAsset.xdm__asset__first_observed | unknown | The timestamp when the asset was first observed, in ISO 8601 format. |
| Core.CoreAsset.asset_hierarchy | unknown | The hierarchy or structure representing the asset. |
| Core.CoreAsset.xdm__asset__type__category | unknown | The asset category type. |
| Core.CoreAsset.xdm__asset__cloud__region | unknown | The cloud region where the asset resides. |
| Core.CoreAsset.xdm__asset__module_unstructured_fields | unknown | The unstructured fields or metadata associated with the asset module. |
| Core.CoreAsset.xdm__asset__source | unknown | The originating source of the asset's information. |
| Core.CoreAsset.xdm__asset__id | unknown | The source unique identifier for the asset. |
| Core.CoreAsset.xdm__asset__type__class | unknown | The classification or type class of the asset. |
| Core.CoreAsset.xdm__asset__type__name | unknown | The specific name of the asset type. |
| Core.CoreAsset.xdm__asset__strong_id | unknown | The strong or immutable identifier for the asset. |
| Core.CoreAsset.xdm__asset__name | unknown | The name of the asset. |
| Core.CoreAsset.xdm__asset__raw_fields | unknown | The raw fields or unprocessed data related to the asset. |
| Core.CoreAsset.xdm__asset__normalized_fields | unknown | The normalized fields associated with the asset. |
| Core.CoreAsset.all_sources | unknown | A list of all sources providing information about the asset. |

##### Command Example

```!core-get-asset-details asset_id=123```

##### Context Example

```
{
    "Core.CoreAsset": [
        {
            "asset_hierarchy": ["123"],
            "xdm__asset__type__category": "Policy",
            "xdm__asset__cloud__region": "Global",
            "xdm__asset__module_unstructured_fields": {},
            "xdm__asset__source": "XSIAM",
            "xdm__asset__id": "123",
            "xdm__asset__type__class": "Identity",
            "xdm__asset__normalized_fields": {},
            "xdm__asset__first_observed": 100000000,
            "xdm__asset__last_observed": 100000000,
            "xdm__asset__name": "Fake Name",
            "xdm__asset__type__name": "IAM",
            "xdm__asset__strong_id": "FAKE ID"
        }
    ]
}
```

##### Human Readable Output

>| asset_hierarchy | xdm__asset__type__category | xdm__asset__cloud__region | xdm__asset__module_unstructured_fields | xdm__asset__source | xdm__asset__id | xdm__asset__type__class | xdm__asset__normalized_fields | xdm__asset__first_observed | xdm__asset__last_observed | xdm__asset__name | xdm__asset__type__name | xdm__asset__strong_id |
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|123|Policy|Global||XSIAM|123|Identity||100000000|100000000|Fake Name|IAM|FAKE ID|

### core-get-issues

***
Returns a list of issues and their metadata, which you can filter by built-in arguments or use the custom_filter to input a JSON filter object.
Multiple filter arguments will be concatenated using the AND operator, while arguments that support a comma-separated list of values will use an OR operator between each value.

#### Base Command

`core-get-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | The unique ID of the issue. Accepts a comma-separated list. | Optional |
| severity | The severity of the issue. Accepts a comma-separated list. Possible values are: low, medium, high, critical. | Optional |
| custom_filter | A custom filter. When using this argument, other filter arguments are not relevant. Example: `{"OR": [{"SEARCH_FIELD": "actor_process_command_line", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "path_to_file"}]}` | Optional |
| Identity_type | Account type. Accepts a comma-separated list. Possible values are: ANONYMOUS, APPLICATION, COMPUTE, FEDERATED_IDENTITY, SERVICE, SERVICE_ACCOUNT, TEMPORARY_CREDENTIALS, TOKEN, UNKNOWN, USER. | Optional |
| agent_id | A unique identifier per agent. Accepts a comma-separated list. | Optional |
| action_external_hostname | The hostname to connect to. In case of a proxy connection, this value will differ from action_remote_ip. Accepts a comma-separated list. | Optional |
| rule_id | A string identifying the user rule. Accepts a comma-separated list. | Optional |
| rule_name | The name of the user rule. Accepts a comma-separated list. | Optional |
| issue_name | The issue name. Accepts a comma-separated list. | Optional |
| issue_source | The issue source. Accepts a comma-separated list. Possible values are: XDR Agent, XDR Analytics, XDR Analytics BIOC, PAN NGFW, XDR BIOC, XDR IOC, Threat Intelligence, XDR Managed Threat Hunting, Correlation, Prisma Cloud, Prisma Cloud Compute, ASM, IoT Security, Custom Alert, Health, SaaS Attachments, Attack Path, Cloud Network Analyzer, IaC Scanner, CAS Secret Scanner, CI/CD Risks, CLI Scanner, CIEM Scanner, API Traffic Monitor, API Posture Scanner, Agentless Disk Scanner, Kubernetes Scanner, Compute Policy, CSPM Scanner, CAS CVE Scanner, CAS License Scanner, Secrets Scanner, SAST Scanner, Data Policy, Attack Surface Test, Package Operational Risk, Vulnerability Policy, AI Security Posture. | Optional |
| time_frame | Supports relative or custom time options. If you choose custom, use the start_time and end_time arguments. Possible values are: 60 minutes, 3 hours, 12 hours, 24 hours, 2 days, 7 days, 14 days, 30 days, custom. | Optional |
| user_name | The name assigned to the user_id during agent runtime. Accepts a comma-separated list. | Optional |
| actor_process_image_name | The file name of the binary file. Accepts a comma-separated list. | Optional |
| causality_actor_process_image_command_line | SHA256 Causality Graph Object command line. Accepts a comma-separated list. | Optional |
| actor_process_image_command_line | Command line used by the process image initiated by the causality actor. Accepts a comma-separated list. | Optional |
| action_process_image_command_line | SHA256 The command line of the process created. Accepts a comma-separated list. | Optional |
| actor_process_image_sha256 | SHA256 hash of the binary file. Accepts a comma-separated list. | Optional |
| causality_actor_process_image_sha256 | SHA256 hash of the binary file. Accepts a comma-separated list. | Optional |
| action_process_image_sha256 | SHA256 of the binary file. Accepts a comma-separated list. | Optional |
| action_file_image_sha256 | SHA256 of the file related to the event. Accepts a comma-separated list. | Optional |
| action_registry_name | The name of the registry. Accepts a comma-separated list. | Optional |
| action_registry_key_data | The key data of the registry. Accepts a comma-separated list. | Optional |
| host_ip | The host IP address. Accepts a comma-separated list. | Optional |
| action_local_ip | The local IP address for the connection. Accepts a comma-separated list. | Optional |
| action_remote_ip | Remote IP address for the connection. Accepts a comma-separated list. | Optional |
| issue_action_status | Issue action status. Possible values are: detected, detected (allowed the session), detected (download), detected (forward), detected (post detected), detected (prompt allow), detected (raised an alert), detected (reported), detected (on write), detected (scanned), detected (sinkhole), detected (syncookie sent), detected (wildfire upload failure), detected (wildfire upload success), detected (wildfire upload skip), detected (xdr managed threat hunting), prevented (block), prevented (blocked), prevented (block-override), prevented (blocked the url), prevented (blocked the ip), prevented (continue), prevented (denied the session), prevented (dropped all packets), prevented (dropped the session), prevented (dropped the session and sent a tcp reset), prevented (dropped the packet), prevented (override), prevented (override-lockout), prevented (post detected), prevented (prompt block), prevented (random-drop), prevented (silently dropped the session with an icmp unreachable message to the host or application), prevented (terminated the session and sent a tcp reset to both sides of the connection), prevented (terminated the session and sent a tcp reset to the client), prevented (terminated the session and sent a tcp reset to the server), prevented (on write). | Optional |
| action_local_port | The local port for the connection. Accepts a comma-separated list. | Optional |
| action_remote_port | The remote port for the connection. Accepts a comma-separated list. | Optional |
| dst_action_external_hostname | The hostname to connect to. In case of a proxy connection, this value will differ from action_remote_ip. Accepts a comma-separated list. | Optional |
| sort_field | The field by which to sort the results. Default is source_insert_ts. | Optional |
| sort_order | The order in which to sort the results. Possible values are: DESC, ASC. | Optional |
| offset | The first page number to retrieve issues from. Default is 0. | Optional |
| limit | The last page number to retrieve issues from. Default is 50. | Optional |
| start_time | Relevant when the time_frame argument is set to custom. Supports epoch timestamp and simplified extended ISO format (YYYY-MM-DDThh:mm:ss). | Optional |
| end_time | Relevant when the time_frame argument is set to custom. Supports epoch timestamp and simplified extended ISO format (YYYY-MM-DDThh:mm:ss). | Optional |
| starred | Whether the issue is starred. Possible values are: true, false. | Optional |
| mitre_technique_id_and_name | The MITRE attack technique. Accepts a comma-separated list. | Optional |
| issue_category | The category of the issue. Accepts a comma-separated list. | Optional |
| issue_domain | The domain of the issue. Accepts a comma-separated list. Possible values are: Health, Hunting, IT, Posture, Security. | Optional |
| issue_description | The description of the issue. Accepts a comma-separated list. | Optional |
| os_actor_process_image_sha256 | The SHA256 hash of the OS actor process image. Accepts a comma-separated list. | Optional |
| action_file_macro_sha256 | The SHA256 hash of the action file macro. Accepts a comma-separated list. | Optional |
| status | The status progress. Accepts a comma-separated list. Possible values are: New, In Progress, Resolved. | Optional |
| not_status | Not status progress. Accepts a comma-separated list. Possible values are: New, In Progress, Resolved. | Optional |
| asset_ids | The assets IDs related to the issue. Accepts a comma-separated list. | Optional |
| assignee | The assignee of the issue. Accepts a comma-separated list. | Optional |
| output_keys | A comma separated list of outputs to include in the context. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Issue.internal_id | String | The unique ID of the issue. |
| Core.Issue.source_insert_ts | Number | The detection timestamp. |
| Core.Issue.issue_name | String | The name of the issue. |
| Core.Issue.severity | String | The severity of the issue. |
| Core.Issue.issue_category | String | The category of the issue. |
| Core.Issue.issue_action_status | String | The issue action status. |
| Core.Issue.issue_action_status_readable | String | The issue action status in readable format. |
| Core.Issue.issue_description | String | The issue description. |
| Core.Issue.agent_ip_addresses | String | The host IP address. |
| Core.Issue.agent_hostname | String | The hostname. |
| Core.Issue.mitre_tactic_id_and_name | String | The MITRE attack tactic. |
| Core.Issue.mitre_technique_id_and_name | String | The MITRE attack technique. |
| Core.Issue.starred | Boolean | Whether the issue is starred. |

### core-get-case-extra-data

***
Get extra data fields of a specific case including issues and key artifacts.

#### Base Command

`core-get-case-extra-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | A comma seperated list of case IDs. | Required |
| issues_limit | Maximum number of issues to return per case. The default and maximum is 1000. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.CaseExtraData.case.case_id | String | The unique identifier for the case. |
| Core.CaseExtraData.case.case_name | String | The name assigned to the case. |
| Core.CaseExtraData.case.creation_time | Number | The timestamp \(in epoch format\) when the case was created. |
| Core.CaseExtraData.case.modification_time | Number | The timestamp \(in epoch format\) when the case was last modified. |
| Core.CaseExtraData.case.detection_time | String | The timestamp when the activity related to the case was first detected. |
| Core.CaseExtraData.case.status | String | The current status of the case \(e.g., 'new', 'under_investigation', 'closed'\). |
| Core.CaseExtraData.case.severity | String | The severity level of the case \(e.g., 'low', 'medium', 'high', 'critical'\). |
| Core.CaseExtraData.case.description | String | A detailed textual description of the case. |
| Core.CaseExtraData.case.assigned_user_mail | String | The email address of the user assigned to the case. |
| Core.CaseExtraData.case.assigned_user_pretty_name | String | The display name of the user assigned to the case. |
| Core.CaseExtraData.case.issue_count | Number | The total number of issues associated with the case. |
| Core.CaseExtraData.case.low_severity_issue_count | Number | The total number of low-severity issues within the case. |
| Core.CaseExtraData.case.med_severity_issue_count | Number | The total number of medium-severity issues within the case. |
| Core.CaseExtraData.case.high_severity_issue_count | Number | The total number of high-severity issues within the case. |
| Core.CaseExtraData.case.critical_severity_issue_count | Number | The total number of critical-severity issues within the case. |
| Core.CaseExtraData.case.user_count | Number | The number of unique users involved in the case. |
| Core.CaseExtraData.case.host_count | Number | The number of unique hosts involved in the case. |
| Core.CaseExtraData.case.notes | Array | A collection of notes or comments added to the case by analysts. |
| Core.CaseExtraData.case.resolve_comment | String | The comment entered by a user when resolving the case. |
| Core.CaseExtraData.case.manual_severity | String | The severity level manually set by a user, which may override the calculated severity for the case. |
| Core.CaseExtraData.case.manual_description | String | A description of the case that was manually entered by a user. |
| Core.CaseExtraData.case.xdr_url | String | The direct URL to view the case in the XDR platform. |
| Core.CaseExtraData.case.starred | Boolean | A flag indicating whether the case has been starred or marked as a favorite. |
| Core.CaseExtraData.case.hosts | Array | A comma-separated list of hostnames involved in the case. |
| Core.CaseExtraData.case.case_sources | String | The products or sources that contributed issues to this case \(e.g., 'XDR Agent', 'Firewall'\). |
| Core.CaseExtraData.case.rule_based_score | Number | The case's risk score as calculated by automated detection rules. |
| Core.CaseExtraData.case.manual_score | Number | A risk score manually assigned to the case by a user. |
| Core.CaseExtraData.case.wildfire_hits | Number | The number of times a file associated with this case was identified as malicious by WildFire. |
| Core.CaseExtraData.case.issues_grouping_status | String | The current status of the issue grouping or clustering process for this case. |
| Core.CaseExtraData.case.mitre_techniques_ids_and_names | String | A list of MITRE ATT&amp;CK technique IDs and names observed in the case. |
| Core.CaseExtraData.case.mitre_tactics_ids_and_names | String | A list of MITRE ATT&amp;CK tactic IDs and names observed in the case. |
| Core.CaseExtraData.case.issue_categories | String | A comma-separated list of categories for the issues included in the case. |
| Core.CaseExtraData.issues.total_count | Number | The total number of individual issues that are part of the case. |
| Core.CaseExtraData.issues.data.external_id | String | The unique external identifier for an individual issue. |
| Core.CaseExtraData.issues.data.severity | String | The severity of the individual issue. |
| Core.CaseExtraData.issues.data.matching_status | String | The correlation status for the issue. |
| Core.CaseExtraData.issues.data.end_match_attempt_ts | Date | The timestamp of the last attempt to match the issue with others. |
| Core.CaseExtraData.issues.data.local_insert_ts | Date | The timestamp when the issue was first recorded in the system. |
| Core.CaseExtraData.issues.data.bioc_indicator | String | The specific Behavioral Indicator of Compromise \(BIOC\) that triggered the issue. |
| Core.CaseExtraData.issues.data.matching_service_rule_id | String | The ID of the matching service rule that identified the issue. |
| Core.CaseExtraData.issues.data.attempt_counter | Number | The number of times a matching attempt has been made for this issue. |
| Core.CaseExtraData.issues.data.bioc_category_enum_key | String | The key representing the category of the Behavioral Indicator of Compromise \(BIOC\). |
| Core.CaseExtraData.issues.data.case_id | Number | The ID of the case to which this issue belongs. |
| Core.CaseExtraData.issues.data.is_whitelisted | Boolean | A flag indicating whether this issue has been whitelisted or suppressed. |
| Core.CaseExtraData.issues.data.starred | Boolean | A flag indicating whether this individual issue has been starred. |
| Core.CaseExtraData.issues.data.deduplicate_tokens | String | Tokens used to identify and deduplicate similar issues. |
| Core.CaseExtraData.issues.data.filter_rule_id | String | The ID of any filter rule that was applied to this issue. |
| Core.CaseExtraData.issues.data.mitre_technique_id_and_name | String | The specific MITRE ATT&amp;CK technique ID and name associated with the issue. |
| Core.CaseExtraData.issues.data.mitre_tactic_id_and_name | String | The specific MITRE ATT&amp;CK tactic ID and name associated with the issue. |
| Core.CaseExtraData.issues.data.agent_version | String | The version of the agent installed on the endpoint related to the issue. |
| Core.CaseExtraData.issues.data.agent_device_domain | String | The domain of the endpoint device. |
| Core.CaseExtraData.issues.data.agent_fqdn | String | The fully qualified domain name \(FQDN\) of the agent's host. |
| Core.CaseExtraData.issues.data.agent_os_type | String | The operating system type of the endpoint \(e.g., 'Windows', 'Linux'\). |
| Core.CaseExtraData.issues.data.agent_os_sub_type | String | The specific version or distribution of the agent's operating system. |
| Core.CaseExtraData.issues.data.agent_data_collection_status | String | The status of the agent's data collection process. |
| Core.CaseExtraData.issues.data.mac | String | The primary MAC address of the endpoint. |
| Core.CaseExtraData.issues.data.mac_addresses | Array | A list of all MAC addresses associated with the endpoint. |
| Core.CaseExtraData.issues.data.agent_is_vdi | Boolean | A flag indicating whether the agent is installed on a Virtual Desktop Infrastructure \(VDI\) instance. |
| Core.CaseExtraData.issues.data.agent_install_type | String | The installation type of the agent. |
| Core.CaseExtraData.issues.data.agent_host_boot_time | Date | The last boot time of the host where the agent is installed. |
| Core.CaseExtraData.issues.data.event_sub_type | String | A more specific classification of the event type. |
| Core.CaseExtraData.issues.data.module_id | String | The identifier of the agent module that generated the event. |
| Core.CaseExtraData.issues.data.association_strength | Number | A score indicating the strength of the event's association to the case. |
| Core.CaseExtraData.issues.data.dst_association_strength | Number | The association strength related to the destination entity in the event. |
| Core.CaseExtraData.issues.data.story_id | String | An identifier that groups a sequence of related events into a "story". |
| Core.CaseExtraData.issues.data.event_id | String | The unique identifier for the event. |
| Core.CaseExtraData.issues.data.event_type | String | The primary type of the event \(e.g., 'Process Execution', 'Network Connection'\). |
| Core.CaseExtraData.issues.data.events_length | Number | The number of raw events that were aggregated to create this issue. |
| Core.CaseExtraData.issues.data.event_timestamp | Date | The timestamp when the original event occurred. |
| Core.CaseExtraData.issues.data.actor_process_instance_id | String | The unique instance ID of the primary actor process. |
| Core.CaseExtraData.issues.data.actor_process_image_path | String | The full file path of the actor process's executable. |
| Core.CaseExtraData.issues.data.actor_process_image_name | String | The filename of the actor process's executable. |
| Core.CaseExtraData.issues.data.actor_process_command_line | String | The command line used to launch the actor process. |
| Core.CaseExtraData.issues.data.actor_process_signature_status | String | The digital signature status of the actor process executable \(e.g., 'Signed', 'Unsigned'\). |
| Core.CaseExtraData.issues.data.actor_process_signature_vendor | String | The vendor name from the digital signature of the actor process. |
| Core.CaseExtraData.issues.data.actor_process_image_sha256 | String | The SHA256 hash of the actor process executable. |
| Core.CaseExtraData.issues.data.actor_process_image_md5 | String | The MD5 hash of the actor process executable. |
| Core.CaseExtraData.issues.data.actor_process_causality_id | String | The causality ID of the actor process, which links it to its parent process. |
| Core.CaseExtraData.issues.data.actor_causality_id | String | The causality ID of the primary actor in the event. |
| Core.CaseExtraData.issues.data.actor_process_os_pid | String | The operating system's Process ID \(PID\) of the actor process. |
| Core.CaseExtraData.issues.data.actor_thread_thread_id | String | The ID of the specific thread within the actor process that initiated the action. |
| Core.CaseExtraData.issues.data.causality_actor_process_image_name | String | The image name of the process that initiated the actor process \(the grandparent\). |
| Core.CaseExtraData.issues.data.causality_actor_process_command_line | String | The command line of the causality actor process. |
| Core.CaseExtraData.issues.data.causality_actor_process_image_path | String | The file path of the causality actor process's executable. |
| Core.CaseExtraData.issues.data.causality_actor_process_signature_vendor | String | The signature vendor of the causality actor process. |
| Core.CaseExtraData.issues.data.causality_actor_process_signature_status | String | The signature status of the causality actor process. |
| Core.CaseExtraData.issues.data.causality_actor_causality_id | String | The causality ID of the causality actor process. |
| Core.CaseExtraData.issues.data.causality_actor_process_execution_time | Date | The execution timestamp of the causality actor process. |
| Core.CaseExtraData.issues.data.causality_actor_process_image_md5 | String | The MD5 hash of the causality actor process's executable. |
| Core.CaseExtraData.issues.data.causality_actor_process_image_sha256 | String | The SHA256 hash of the causality actor process's executable. |
| Core.CaseExtraData.issues.data.action_file_path | String | The file path of the file that was the target of an action. |
| Core.CaseExtraData.issues.data.action_file_name | String | The name of the file that was the target of an action. |
| Core.CaseExtraData.issues.data.action_file_md5 | String | The MD5 hash of the file that was the target of an action. |
| Core.CaseExtraData.issues.data.action_file_sha256 | String | The SHA256 hash of the file that was the target of an action. |
| Core.CaseExtraData.issues.data.action_file_macro_sha256 | String | The SHA256 hash of a macro embedded within the target file. |
| Core.CaseExtraData.issues.data.action_registry_data | String | The data written to or read from a registry value during the action. |
| Core.CaseExtraData.issues.data.action_registry_key_name | String | The name of the registry key involved in the action. |
| Core.CaseExtraData.issues.data.action_registry_value_name | String | The name of the registry value involved in the action. |
| Core.CaseExtraData.issues.data.action_registry_full_key | String | The full path of the registry key involved in the action. |
| Core.CaseExtraData.issues.data.action_local_ip | String | The local IP address involved in a network action. |
| Core.CaseExtraData.issues.data.action_local_port | String | The local port number involved in a network action. |
| Core.CaseExtraData.issues.data.action_remote_ip | String | The remote IP address involved in a network action. |
| Core.CaseExtraData.issues.data.action_remote_port | String | The remote port number involved in a network action. |
| Core.CaseExtraData.issues.data.action_external_hostname | String | The external hostname or domain associated with the network action. |
| Core.CaseExtraData.issues.data.action_country | String | The country associated with the remote IP address in the network action. |
| Core.CaseExtraData.issues.data.action_process_instance_id | String | The instance ID of the process that was the target of an action. |
| Core.CaseExtraData.issues.data.action_process_causality_id | String | The causality ID of the target process. |
| Core.CaseExtraData.issues.data.action_process_image_name | String | The executable name of the target process. |
| Core.CaseExtraData.issues.data.action_process_image_sha256 | String | The SHA256 hash of the target process's executable. |
| Core.CaseExtraData.issues.data.action_process_image_command_line | String | The command line of the target process. |
| Core.CaseExtraData.issues.data.action_process_signature_status | String | The signature status of the target process. |
| Core.CaseExtraData.issues.data.action_process_signature_vendor | String | The signature vendor of the target process. |
| Core.CaseExtraData.issues.data.os_actor_effective_username | String | The effective username of the OS-level actor responsible for the event. |
| Core.CaseExtraData.issues.data.os_actor_process_instance_id | String | The instance ID of the OS actor process. |
| Core.CaseExtraData.issues.data.os_actor_process_image_path | String | The file path of the OS actor process's executable. |
| Core.CaseExtraData.issues.data.os_actor_process_image_name | String | The image name of the OS actor process. |
| Core.CaseExtraData.issues.data.os_actor_process_command_line | String | The command line of the OS actor process. |
| Core.CaseExtraData.issues.data.os_actor_process_signature_status | String | The signature status of the OS actor process. |
| Core.CaseExtraData.issues.data.os_actor_process_signature_vendor | String | The signature vendor of the OS actor process. |
| Core.CaseExtraData.issues.data.os_actor_process_image_sha256 | String | The SHA256 hash of the OS actor process's executable. |
| Core.CaseExtraData.issues.data.os_actor_process_causality_id | String | The causality ID of the OS actor process. |
| Core.CaseExtraData.issues.data.os_actor_causality_id | String | The causality ID of the OS actor. |
| Core.CaseExtraData.issues.data.os_actor_process_os_pid | String | The operating system PID of the OS actor process. |
| Core.CaseExtraData.issues.data.os_actor_thread_thread_id | String | The thread ID of the OS actor. |
| Core.CaseExtraData.issues.data.fw_app_id | String | The firewall application ID for the traffic. |
| Core.CaseExtraData.issues.data.fw_interface_from | String | The firewall interface from which the traffic originated. |
| Core.CaseExtraData.issues.data.fw_interface_to | String | The firewall interface to which the traffic was destined. |
| Core.CaseExtraData.issues.data.fw_rule | String | The name of the firewall rule that matched the traffic. |
| Core.CaseExtraData.issues.data.fw_rule_id | String | The unique ID of the firewall rule that matched the traffic. |
| Core.CaseExtraData.issues.data.fw_device_name | String | The name of the firewall device that logged the event. |
| Core.CaseExtraData.issues.data.fw_serial_number | String | The serial number of the firewall device. |
| Core.CaseExtraData.issues.data.fw_url_domain | String | The domain visited, as logged by the firewall. |
| Core.CaseExtraData.issues.data.fw_email_subject | String | The subject line of an email, as logged by the firewall. |
| Core.CaseExtraData.issues.data.fw_email_sender | String | The sender of an email, as logged by the firewall. |
| Core.CaseExtraData.issues.data.fw_email_recipient | String | The recipient of an email, as logged by the firewall. |
| Core.CaseExtraData.issues.data.fw_app_subcategory | String | The application subcategory as identified by the firewall. |
| Core.CaseExtraData.issues.data.fw_app_category | String | The application category as identified by the firewall. |
| Core.CaseExtraData.issues.data.fw_app_technology | String | The application technology as identified by the firewall. |
| Core.CaseExtraData.issues.data.fw_vsys | String | The virtual system on the firewall that processed the traffic. |
| Core.CaseExtraData.issues.data.fw_xff | String | The X-Forwarded-For \(XFF\) header value from the traffic. |
| Core.CaseExtraData.issues.data.fw_misc | String | Miscellaneous firewall log data. |
| Core.CaseExtraData.issues.data.fw_is_phishing | Boolean | A flag indicating if the firewall identified the event as phishing. |
| Core.CaseExtraData.issues.data.dst_agent_id | String | The agent ID of the destination endpoint in a lateral movement event. |
| Core.CaseExtraData.issues.data.dst_causality_actor_process_execution_time | Date | The execution time of the causality actor process on the destination endpoint. |
| Core.CaseExtraData.issues.data.dns_query_name | String | The domain name in a DNS query event. |
| Core.CaseExtraData.issues.data.dst_action_external_hostname | String | The external hostname of the destination. |
| Core.CaseExtraData.issues.data.dst_action_country | String | The country of the destination. |
| Core.CaseExtraData.issues.data.dst_action_external_port | String | The external port of the destination. |
| Core.CaseExtraData.issues.data.issue_id | String | The unique identifier for the issue. |
| Core.CaseExtraData.issues.data.detection_timestamp | Number | The timestamp when the issue was first detected. |
| Core.CaseExtraData.issues.data.name | String | The name or title of the issue. |
| Core.CaseExtraData.issues.data.category | String | The category of the issue. |
| Core.CaseExtraData.issues.data.endpoint_id | String | The unique ID of the endpoint where the issue occurred. |
| Core.CaseExtraData.issues.data.description | String | A detailed description of the issue. |
| Core.CaseExtraData.issues.data.host_ip | String | The IP address of the host related to the issue. |
| Core.CaseExtraData.issues.data.host_name | String | The hostname of the endpoint related to the issue. |
| Core.CaseExtraData.issues.data.source | String | The source of the issue \(e.g., 'XDR'\). |
| Core.CaseExtraData.issues.data.action | String | The action taken in response to the event \(e.g., 'detected', 'prevented'\). |
| Core.CaseExtraData.issues.data.action_pretty | String | A user-friendly representation of the action taken. |
| Core.CaseExtraData.issues.data.user_name | String | The name of the user associated with the issue. |
| Core.CaseExtraData.issues.data.contains_featured_host | Boolean | A flag indicating if the issue involves a host marked as featured or critical. |
| Core.CaseExtraData.issues.data.contains_featured_user | Boolean | A flag indicating if the issue involves a user marked as featured or critical. |
| Core.CaseExtraData.issues.data.contains_featured_ip_address | Boolean | A flag indicating if the issue involves an IP address marked as featured or critical. |
| Core.CaseExtraData.issues.data.tags | String | Any tags that have been applied to the issue. |
| Core.CaseExtraData.issues.data.original_tags | String | The original set of tags applied to the issue before any modifications. |
| Core.CaseExtraData.network_artifacts.total_count | Number | The total number of network artifacts associated with the case. |
| Core.CaseExtraData.network_artifacts.data.type | String | The type of network artifact \(e.g., 'IP Address', 'Domain'\). |
| Core.CaseExtraData.network_artifacts.data.issue_count | Number | The number of issues in the case that involve this network artifact. |
| Core.CaseExtraData.network_artifacts.data.is_manual | Boolean | A flag indicating if the network artifact was added manually by a user. |
| Core.CaseExtraData.network_artifacts.data.network_domain | String | The domain name of the network artifact. |
| Core.CaseExtraData.network_artifacts.data.network_remote_ip | String | The remote IP address of the network artifact. |
| Core.CaseExtraData.network_artifacts.data.network_remote_port | String | The remote port number of the network artifact. |
| Core.CaseExtraData.network_artifacts.data.network_country | String | The country associated with the network artifact's IP address. |
| Core.CaseExtraData.file_artifacts.total_count | Number | The total number of file artifacts associated with the case. |
| Core.CaseExtraData.file_artifacts.data.issue_count | Number | The number of issues in the case that involve this file artifact. |
| Core.CaseExtraData.file_artifacts.data.file_name | String | The name of the file artifact. |
| Core.CaseExtraData.file_artifacts.data.File_sha256 | String | The SHA256 hash of the file artifact. |
| Core.CaseExtraData.file_artifacts.data.file_signature_status | String | The digital signature status of the file artifact. |
| Core.CaseExtraData.file_artifacts.data.file_wildfire_verdict | String | The verdict from WildFire for this file \(e.g., 'malicious', 'benign'\). |
| Core.CaseExtraData.file_artifacts.data.is_malicous | Boolean | A flag indicating whether the file artifact is considered malicious. |
| Core.CaseExtraData.file_artifacts.data.is_manual | Boolean | A flag indicating if the file artifact was added manually by a user. |
| Core.CaseExtraData.file_artifacts.data.is_process | Boolean | A flag indicating if the file artifact is a process executable. |
| Core.CaseExtraData.file_artifacts.data.low_confidence | Boolean | A flag indicating if the verdict on the file artifact has low confidence. |
| Core.CaseExtraData.file_artifacts.data.type | String | The type of the file artifact. |

### core-get-cases

***
Get case information based on the specified filters.

#### Base Command

`core-get-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lte_creation_time | A date in the format 2019-12-31T23:59:00. Only cases that were created on or before the specified date/time will be retrieved. | Optional |
| gte_creation_time | A date in the format 2019-12-31T23:59:00. Only cases that were created on or after the specified date/time will be retrieved. | Optional |
| lte_modification_time | Filters returned cases that were created on or before the specified date/time, in the format 2019-12-31T23:59:00. | Optional |
| gte_modification_time | Filters returned cases that were modified on or after the specified date/time, in the format 2019-12-31T23:59:00. | Optional |
| case_id_list | A comma seperated list of case IDs. | Optional |
| since_creation_time | Filters returned cases that were created on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. | Optional |
| since_modification_time | Filters returned cases that were modified on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. | Optional |
| sort_by_modification_time | Sorts returned cases by the date/time that the case was last modified ("asc" - ascending, "desc" - descending). Possible values are: asc, desc. | Optional |
| sort_by_creation_time | Sorts returned cases by the date/time that the case was created ("asc" - ascending, "desc" - descending). Possible values are: asc, desc. | Optional |
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional |
| limit | Maximum number of cases to return per page. The default and maximum value is 60. Default is 60. | Optional |
| case_domain | A comma-separated list of domains to filter cases by. | Optional |
| status | A comma-separated list of case statuses to filter cases by. Possible values are: new, under_investigation, resolved. | Optional |
| severity | A comma-separated list of severity levels to filter cases by. Possible values are: low, medium, high, critical. | Optional |
| asset_ids | A comma-separated list of Asset IDs associated with the case by which to filter the cases. | Optional |
| asset_groups | A comma-separated list of Asset Group IDs, where the case is filtered by the assets contained within those groups. | Optional |
| hosts | A comma-separated list of hosts to filter cases by. | Optional |
| tags | A comma-separated list of tags to filter cases by. | Optional |
| assignee | A comma-separated list of assignee names or emails to filter cases by. | Optional |
| starred | Filter cases by whether they are starred or not. Possible values are: true, false. | Optional |
| case_name | A comma-separated list of names to filter cases by. | Optional |
| case_description | A comma-separated list of descriptions to filter cases by. | Optional |
| get_enriched_case_data | Whether to include enriched case data in the response. Recommended for up to 10 cases. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Case.case_id | String | Unique ID assigned to each returned case. |
| Core.Case.case_name | String | Name of the case. |
| Core.Case.creation_time | Number | Timestamp when the case was created. |
| Core.Case.modification_time | Number | Timestamp when the case was last modified. |
| Core.Case.status | String | Current status of the case. |
| Core.Case.severity | String | Severity level of the case. |
| Core.Case.description | String | Description of the case. |
| Core.Case.assigned_user_mail | String | Email address of the assigned user. May be null. |
| Core.Case.assigned_user_pretty_name | String | Full name of the assigned user. May be null. |
| Core.Case.issue_count | Number | Total number of issues in the case. |
| Core.Case.low_severity_issue_count | Number | Number of issues with low severity. |
| Core.Case.med_severity_issue_count | Number | Number of issues with medium severity. |
| Core.Case.high_severity_issue_count | Number | Number of issues with high severity. |
| Core.Case.critical_severity_issue_count | Number | Number of issues with critical severity. |
| Core.Case.user_count | Number | Number of users involved in the case. |
| Core.Case.host_count | Number | Number of hosts involved in the case. |
| Core.Case.resolve_comment | String | Comments added when resolving the case. May be null. |
| Core.Case.resolved_timestamp | Number | Timestamp when the case was resolved. |
| Core.Case.manual_severity | Number | Severity manually assigned by the user. May be null. |
| Core.Case.starred | Boolean | Indicates whether the case is starred. |
| Core.Case.hosts | Array | List of hosts involved in the case. |
| Core.Case.users | Array | List of users involved in the case. |
| Core.Case.case_sources | Array | Sources of the case. |
| Core.Case.rule_based_score | Number | Score based on rules. |
| Core.Case.manual_score | Number | Manually assigned score. May be null. |
| Core.Case.wildfire_hits | Number | Number of WildFire hits. |
| Core.Case.issues_grouping_status | String | Status of issue grouping. |
| Core.Case.mitre_tactics_ids_and_names | Array | List of MITRE ATT&amp;CK tactic IDs and names associated with the case. |
| Core.Case.mitre_techniques_ids_and_names | Array | List of MITRE ATT&amp;CK technique IDs and names associated with the case. |
| Core.Case.issue_categories | Array | Categories of issues associated with the case. |
| Core.Case.original_tags | Array | Original tags assigned to the case. |
| Core.Case.tags | Array | Current tags assigned to the case. |
| Core.Case.case_domain | String | Domain associated with the case. |
| Core.Case.custom_fields | Unknown | Custom fields for the case with standardized lowercase, whitespace-free names. |
| Core.Case.CaseExtraData.issue_ids | Array | List of issue IDs associated with the case. |
| Core.Case.CaseExtraData.file_artifacts | Array | File artifacts associated with the case. |
| Core.Case.CaseExtraData.network_artifacts | Array | Network artifacts associated with the case. |
| Core.Case.CaseExtraData.starred_manually | Boolean | True if the case was starred manually; false if starred by rules. |
| Core.Case.CaseExtraData.xdr_url | String | URL to view the case in Cortex XDR. |
| Core.Case.CaseExtraData.manual_description | String | Description manually provided by the user. |
| Core.Case.CaseExtraData.notes | String | The notes related to the case. |
| Core.Case.CaseExtraData.detection_time | Date | The timestamp when the first issue was detected in the case. |
| Core.CasesMetadata.returned_count | String | The actual number of cases that match all filter criteria and returned in this specific response. |
| Core.CasesMetadata.filtered_count | String | The total number of cases in the system that match all filter criteria. |

### core-search-asset-groups

***
Retrieve asset groups from the Cortex platform with optional filtering.

#### Base Command

`core-search-asset-groups`

#### Input

| name | JSON list of asset groups to search for. (e.g. `["group1", "group2"]`). | Optional |
| type | Filter asset groups by type. | Optional |
| description | JSON list of descriptions to search for. (e.g. `["description1", "description2"]`). | Optional |
| limit | The maximum number of groups to return. | Optional |
| id | Comma separated list of ids to search for. | Optional |

#### Context Output

| Core.AssetGroups.name | String | The name of the asset group. |
| Core.AssetGroups.filter | String | The filter criteria for the asset group. |
| Core.AssetGroups.membership_predicate | String | The predicate used to create the asset group. |
| Core.AssetGroups.type | String | The type of the asset group. |
| Core.AssetGroups.description | String | The description of the asset group. |
| Core.AssetGroups.modified_by | String | The user who modified the asset group. |
| Core.AssetGroups.modified_by_pretty | String | The formatted name of the user who created the asset group. |
| Core.AssetGroups.created_by | String | The user who created the asset group. |
| Core.AssetGroups.created_by_pretty | String | The formatted name of the user who created the asset group. |

### core-get-vulnerabilities

***
Retrieves vulnerabilities based on specified filters.

#### Base Command

`core-get-vulnerabilities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of vulnerabilities to return. Default is 50. | Optional |
| sort_field | The field by which to sort the results. Default is LAST_OBSERVED. | Optional |
| sort_order | The order in which to sort the results. Possible values are: DESC, ASC. | Optional |
| cve_id | The CVE ID. Accepts a comma-separated list. | Optional |
| issue_id | The issue ID. Accepts a comma-separated list. | Optional |
| cvss_score_gte | The minimum CVSS score. | Optional |
| epss_score_gte | The minimum EPSS score. | Optional |
| internet_exposed | Filter by internet exposed assets. Possible values are: true, false. | Optional |
| exploitable | Filter by exploitable vulnerabilities. Possible values are: true, false. | Optional |
| has_kev | Filter by vulnerabilities that have a Known Exploited Vulnerability (KEV). Possible values are: true, false. | Optional |
| affected_software | Filter by affected software. Accepts a comma-separated list. | Optional |
| on_demand_fields | A comma-separated list of additional fields to retrieve. | Optional |
| start_time | The start time for filtering according to case creation time. Supports free-text relative and absolute times. For example: 7 days ago, 2023-06-15T10:30:00Z, 13/8/2025. | Optional |
| end_time | The end time for filtering according to case creation time. Supports free-text relative and absolute times. For example: 7 days ago, 2023-06-15T10:30:00Z, 13/8/2025. | Optional |
| severity | The severity of the vulnerability issue. Possible values are: info, low, medium, high, critical. | Optional |
| assignee | The email of the user assigned to the vulnerability. Accepts a comma-separated list. <br/>Use 'unassigned' for unassigned vulnerabilities or 'assigned' for all assigned vulnerabilities.<br/>. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.VulnerabilityIssue.ISSUE_ID | String | The unique identifier for the vulnerability issue. |
| Core.VulnerabilityIssue.CVE_ID | String | The CVE identifier for the vulnerability. |
| Core.VulnerabilityIssue.CVE_DESCRIPTION | String | The description of the CVE. |
| Core.VulnerabilityIssue.ASSET_NAME | String | The name of the affected asset. |
| Core.VulnerabilityIssue.PLATFORM_SEVERITY | String | The severity of the vulnerability as determined by the platform. |
| Core.VulnerabilityIssue.EPSS_SCORE | Number | The Exploit Prediction Scoring System \(EPSS\) score. |
| Core.VulnerabilityIssue.CVSS_SCORE | Number | The Common Vulnerability Scoring System \(CVSS\) score. |
| Core.VulnerabilityIssue.ASSIGNED_TO | String | The email of the user assigned to the vulnerability. |
| Core.VulnerabilityIssue.ASSIGNED_TO_PRETTY | String | The full name of the user assigned to the vulnerability. |
| Core.VulnerabilityIssue.AFFECTED_SOFTWARE | Unknown | The software affected by the vulnerability. |
| Core.VulnerabilityIssue.FIX_AVAILABLE | Boolean | Indicates if a fix is available for the vulnerability. |
| Core.VulnerabilityIssue.INTERNET_EXPOSED | Boolean | Indicates if the asset is exposed to the internet. |
| Core.VulnerabilityIssue.HAS_KEV | Boolean | Indicates if the vulnerability is a Known Exploited Vulnerability \(KEV\). |
| Core.VulnerabilityIssue.EXPLOITABLE | Boolean | Indicates if the vulnerability is exploitable. |
| Core.VulnerabilityIssue.ASSET_IDS | String | The unique identifier for the asset. |

### core-search-assets

***
Retrieves asset from the Cortex platform using optional filter criteria.

#### Base Command

`core-search-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The number of assets to return per page. Default is 100. | Optional |
| page_number | The page number for the assets to return for pagination. Default is 0. | Optional |
| asset_names | Comma-separated list of asset names to search for. (e.g., "asset_name1,asset_name2"). | Optional |
| asset_types | Comma-separated list of asset types to search for. (e.g., "asset_type1,asset_type2"). | Optional |
| asset_tags | A JSON encoded string representing a list of tag:value pairs to search for. (e.g., `[{"tag1": "value1"}, {"tag2": "value2"}]`).<br/>. | Optional |
| asset_ids | Comma-separated list of asset IDs to search for. (e.g., "asset_id1,asset_id2"). | Optional |
| asset_providers | Comma-separated list of asset providers to search for. (e.g., "provider1,provider2"). | Optional |
| asset_realms | Comma-separated list of asset realms to search for. (e.g., "realm1,realm2"). | Optional |
| asset_groups | A JSON encoded string representing a list of asset groups to search for. (e.g., `["group1", "group2"]`).<br/>. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Asset.external_provider_id | unknown | The external provider ID of the asset. |
| Core.Asset.first_observed | unknown | The first time the asset was observed. |
| Core.Asset.tags | unknown | The tags of the asset. |
| Core.Asset.realm | unknown | The realm of the asset. |
| Core.Asset.type.id | unknown | The ID of the asset type. |
| Core.Asset.related_issues.critical_issues | unknown | Critical issues related to the asset. |
| Core.Asset.id | unknown | The ID of the asset. |
| Core.Asset.last_observed | unknown | The last time the asset was observed. |
| Core.Asset.type.category | unknown | The category of the asset type. |
| Core.Asset.related_cases.critical_cases | unknown | Critical cases related to the asset. |
| Core.Asset.group_ids | unknown | The group IDs of the asset. |
| Core.Asset.type.class | unknown | The class of the asset type. |
| Core.Asset.related_issues.issues_breakdown | unknown | The related issues breakdown of the asset. |
| Core.Asset.type.name | unknown | The type of the asset. |
| Core.Asset.name | unknown | The name of the asset. |
| Core.Asset.strong_id | unknown | The strong ID of the asset. |
| Core.Asset.cloud.region | unknown | The cloud region of the asset. |
| Core.Asset.related_cases.cases_breakdown | unknown | The related cases breakdown of the asset. |
| Core.Asset.provider | unknown | The asset provider. |

### core-get-issue-recommendations

***
Get comprehensive recommendations for an issue, including remediation steps, playbook suggestions, and recommended actions.

#### Base Command

`core-get-issue-recommendations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_ids | Comma-separated list of IDs of the issues to get recommendations for (maximum 10 per request). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.IssueRecommendations.issue_id | String | The unique identifier for the issue. |
| Core.IssueRecommendations.issue_name | String | The name of the issue. |
| Core.IssueRecommendations.severity | String | The severity of the issue. |
| Core.IssueRecommendations.description | String | Description of the issue. |
| Core.IssueRecommendations.remediation | String | Remediation steps and recommendations for the issue. |
| Core.IssueRecommendations.playbook_suggestions.playbook_id | String | The ID of the suggested playbook. |
| Core.IssueRecommendations.playbook_suggestions.suggestion_rule_id | String | The ID of the suggestion rule that generated this recommendation. |
| Core.IssueRecommendations.playbook_suggestions.name | String | The name of the suggested playbook. |
| Core.IssueRecommendations.playbook_suggestions.comment | String | An explanation of the suggested playbook. |
| Core.IssueRecommendations.quick_action_suggestions.name | String | The name of the suggested quick action. |
| Core.IssueRecommendations.quick_action_suggestions.suggestion_rule_id | String | The ID of the suggestion quick action rule that generated this recommendation. |
| Core.IssueRecommendations.quick_action_suggestions.brand | String | The brand of the quick action. |
| Core.IssueRecommendations.quick_action_suggestions.category | String | The category of the quick action. |
| Core.IssueRecommendations.quick_action_suggestions.description | String | An explanation of the quick action. |
| Core.IssueRecommendations.quick_action_suggestions.pretty_name | String | The display name of the quick action. |
| Core.IssueRecommendations.quick_action_suggestions.arguments.name | String | The argument name. |
| Core.IssueRecommendations.quick_action_suggestions.arguments.prettyName | String | The argument display name. |
| Core.IssueRecommendations.quick_action_suggestions.arguments.prettyPredefined | String | The argument predefined display value. |
| Core.IssueRecommendations.quick_action_suggestions.arguments.description | String | The argument description. |
| Core.IssueRecommendations.quick_action_suggestions.arguments.required | String | Whether the argument is required. |
| Core.IssueRecommendations.existing_code_block | String | Original vulnerable code. |
| Core.IssueRecommendations.suggested_code_block | String | Code block fix suggestion. |

### core-enable-scanners

***
Enable or disable scanners with the specified configuration.

#### Base Command

`core-enable-scanners`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_ids | List of repository asset IDs to configure scanners for. | Required |
| enable_scanners | List of scanners to enable. Possible values are: SECRETS, IAC, SCA. | Optional |
| disable_scanners | List of scanners to disable. Possible values are: SECRETS, IAC, SCA. | Optional |
| secret_validation | Enable live validation of discovered secrets. Possible values are: true, false. | Optional |
| pr_scanning | Enable scanning on pull requests. This argument only relevant when SECRETS scanner is enabled. Possible values are: true, false. | Optional |
| block_on_error | Block deployment on scanner errors. Possible values are: true, false. | Optional |
| tag_resource_blocks | Enable tagging of resource blocks. Possible values are: true, false. | Optional |
| tag_module_blocks | Enable tagging of module blocks. Possible values are: true, false. | Optional |
| exclude_paths | List of file paths to exclude from scanning. | Optional |

### core-get-asset-coverage-histogram

***
Calculates the distribution of values (counts and percentages) for specified categorical fields.

#### Base Command

`core-get-asset-coverage-histogram`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The unique ID of the asset. Accepts a comma-separated list. | Optional |
| asset_name | The name of the asset. Accepts a comma-separated list. | Optional |
| business_application_names | Business application names. Accepts a comma-separated list. | Optional |
| status_coverage | The status coverage. Accepts a comma-separated list. Possible values are: FULLY SCANNED, NOT SCANNED, PARTIALLY SCANNED. | Optional |
| is_scanned_by_vulnerabilities | Is scanned by vulnerabilities. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_code_weakness | Is scanned by code weakness. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_secrets | Is scanned by secrets. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_iac | Is scanned by IaC. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_malware | Is scanned by malware. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_cicd | Is scanned by CICD. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| last_scan_status | The last scan status. Accepts a comma-separated list. Possible values are: NOT_SCANNED_YET, ERROR, COMPLETED. | Optional |
| asset_type | The asset type. Accepts a comma-separated list. Possible values are: CICD PIPELINE, CONTAINER IMAGE REPOSITORY, REPOSITORY. | Optional |
| asset_provider | The asset provider. Accepts a comma-separated list. Possible values are: AWS, AWS_CODE_BUILD, AWS_CODE_COMMIT, AZURE, AZURE_PIPELINES, AZURE_REPOS, BITBUCKET, CIRCLE_CI, DOCKER, GCP, GITHUB, GITHUB_ACTIONS, GITLAB, GITLAB_CI, HCP_TFC_RUN_TASKS, JENKINS, JFROG_ARTIFACTORY, OCI. | Optional |
| vendor_name | The vendor name. Accepts a comma-separated list. Possible values are: AWS, AWS_CODE_BUILD, AWS_CODE_COMMIT, AZURE, AZURE_REPOS, BITBUCKET, BITBUCKET_DATACENTER, CIRCLE_CI, DOCKER, GCP, GITHUB, GITHUB_ACTIONS, GITHUB_ENTERPRISE, GITLAB, GITLAB_SELF_MANAGED, HCP_TFC_RUN_TASKS, HCP_TFE_RUN_TASKS, JENKINS, JFROG_ARTIFACTORY, OCI. | Optional |
| max_values_per_column | The maximum number of distinct values to return for each column. Default is 100. | Optional |
| columns | A list of fields for which to generate histograms. Possible values are: asset_name, business_application_names, status_coverage, is_scanned_by_vulnerabilities, is_scanned_by_code_weakness, is_scanned_by_secrets, is_scanned_by_iac, is_scanned_by_malware, is_scanned_by_cicd, last_scan_status, asset_type, asset_provider, vendor_name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Coverage.Histogram.column_name | String | The column over which the histogram is generated. |
| Core.Coverage.Histogram.data.value | String | The distinct value. |
| Core.Coverage.Histogram.data.count | Number | The number of records with this value after filtering. |
| Core.Coverage.Histogram.data.percentage | Number | The percentage of filtered records with this value. |
| Core.Coverage.Histogram.data.pretty_name | String | A user-friendly label for the value. |

### core-get-asset-coverage

***
Retrieves a list of assets (e.g., Repositories, CI/CD Pipelines, Container Image Repositories) along with their scan coverage status.

#### Base Command

`core-get-asset-coverage`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The unique ID of the asset. Accepts a comma-separated list. | Optional |
| asset_name | The name of the asset. Accepts a comma-separated list. | Optional |
| business_application_names | Business application names. Accepts a comma-separated list. | Optional |
| status_coverage | The status coverage. Accepts a comma-separated list. Possible values are: FULLY SCANNED, NOT SCANNED, PARTIALLY SCANNED. | Optional |
| is_scanned_by_vulnerabilities | Is scanned by vulnerabilities. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_code_weakness | Is scanned by code weakness. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_secrets | Is scanned by secrets. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_iac | Is scanned by IaC. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_malware | Is scanned by malware. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| is_scanned_by_cicd | Is scanned by CICD. Accepts a comma-separated list. Possible values are: DISABLED, ENABLED, IRRELEVANT. | Optional |
| last_scan_status | The last scan status. Accepts a comma-separated list. Possible values are: NOT_SCANNED_YET, ERROR, COMPLETED. | Optional |
| asset_type | The asset type. Accepts a comma-separated list. Possible values are: CICD PIPELINE, CONTAINER IMAGE REPOSITORY, REPOSITORY. | Optional |
| asset_provider | The asset provider. Accepts a comma-separated list. Possible values are: AWS, AWS_CODE_BUILD, AWS_CODE_COMMIT, AZURE, AZURE_PIPELINES, AZURE_REPOS, BITBUCKET, CIRCLE_CI, DOCKER, GCP, GITHUB, GITHUB_ACTIONS, GITLAB, GITLAB_CI, HCP_TFC_RUN_TASKS, JENKINS, JFROG_ARTIFACTORY, OCI. | Optional |
| vendor_name | The vendor name. Accepts a comma-separated list. Possible values are: AWS, AWS_CODE_BUILD, AWS_CODE_COMMIT, AZURE, AZURE_REPOS, BITBUCKET, BITBUCKET_DATACENTER, CIRCLE_CI, DOCKER, GCP, GITHUB, GITHUB_ACTIONS, GITHUB_ENTERPRISE, GITLAB, GITLAB_SELF_MANAGED, HCP_TFC_RUN_TASKS, HCP_TFE_RUN_TASKS, JENKINS, JFROG_ARTIFACTORY, OCI. | Optional |
| limit | The maximum number of assets to return. Default is 100. | Optional |
| sort_field | The field by which to sort the results. Possible values are: asset_id, asset_name, business_application_names, status_coverage, is_scanned_by_vulnerabilities, is_scanned_by_code_weakness, is_scanned_by_secrets, is_scanned_by_iac, is_scanned_by_malware, is_scanned_by_cicd, last_scan_status, asset_type, asset_provider, vendor_name. | Optional |
| sort_order | The order in which to sort the results. Possible values are: DESC, ASC. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Coverage.Asset.asset_id | String | The unique ID of the asset. Each asset is assigned a unique identifier in the system. |
| Core.Coverage.Asset.asset_name | String | The name of the asset. Typically corresponds to the repository, container image, or pipeline name. |
| Core.Coverage.Asset.asset_provider | String | The vendor or source platform of the asset. Indicates where the asset originates from. Possible values: AWS, AWS_CODE_BUILD, AWS_CODE_COMMIT, AZURE, AZURE_REPOS, BITBUCKET, BITBUCKET_DATACENTER, CIRCLE_CI, DOCKER, GCP, GITHUB, GITHUB_ACTIONS, GITHUB_ENTERPRISE, GITLAB, GITLAB_SELF_MANAGED, HCP_TFC_RUN_TASKS, HCP_TFE_RUN_TASKS, JENKINS, JFROG_ARTIFACTORY, OCI. |
| Core.Coverage.Asset.asset_type | String | The type or category of the asset. Determines the nature of the resource being scanned. Possible values: CICD PIPELINE, CONTAINER IMAGE REPOSITORY, REPOSITORY. |
| Core.Coverage.Asset.business_application_names | Array | A list of business applications associated with the asset. These applications help map the asset to business context or ownership. |
| Core.Coverage.Asset.is_scanned_by_cicd | String | Indicates whether the asset is scanned within CI/CD pipelines. Possible values: ENABLED, DISABLED, IRRELEVANT. |
| Core.Coverage.Asset.is_scanned_by_code_weakness | String | Indicates whether code weakness scanning is performed on the asset. Possible values: ENABLED, DISABLED, IRRELEVANT. |
| Core.Coverage.Asset.is_scanned_by_iac | String | Indicates whether infrastructure-as-code \(IaC\) scanning is enabled for the asset. Possible values: ENABLED, DISABLED, IRRELEVANT. |
| Core.Coverage.Asset.is_scanned_by_malware | String | Indicates whether malware scanning is enabled for the asset. Possible values: ENABLED, DISABLED, IRRELEVANT. |
| Core.Coverage.Asset.is_scanned_by_secrets | String | Indicates whether the asset is scanned for hardcoded secrets or credentials. Possible values: ENABLED, DISABLED, IRRELEVANT. |
| Core.Coverage.Asset.is_scanned_by_semgrep | Boolean | Boolean flag indicating whether the asset is analyzed using Semgrep for code issues or misconfigurations. Possible values: true, false. |
| Core.Coverage.Asset.is_scanned_by_sonarqube | Boolean | Boolean flag indicating whether the asset is analyzed using SonarQube for code quality and security issues. Possible values: true, false. |
| Core.Coverage.Asset.is_scanned_by_veracode | Boolean | Boolean flag indicating whether the asset is scanned using Veracode for security vulnerabilities. Possible values: true, false. |
| Core.Coverage.Asset.is_scanned_by_vulnerabilities | String | Indicates whether vulnerability scanning is enabled for the asset. Possible values: ENABLED, DISABLED, IRRELEVANT. |
| Core.Coverage.Asset.last_scan_status | String | The status of the most recent scan performed on the asset. Possible values: NOT_SCANNED_YET, ERROR, COMPLETED. |
| Core.Coverage.Asset.scanners_data | Array | An array containing detailed information from the scanners that evaluated the asset, including scan results, timestamps, and metadata. |
| Core.Coverage.Asset.status_coverage | String | The overall scan coverage of the asset. Possible values: FULLY SCANNED, PARTIALLY SCANNED, NOT SCANNED. |
| Core.Coverage.Asset.unified_provider | String | The unified provider name associated with the asset. Standardized across different vendor integrations. Possible values: AWS, AWS_CODE_BUILD, AWS_CODE_COMMIT, AZURE, AZURE_PIPELINES, AZURE_REPOS, BITBUCKET, CIRCLE_CI, DOCKER, GCP, GITHUB, GITHUB_ACTIONS, GITLAB, GITLAB_CI, HCP_TFC_RUN_TASKS, JENKINS, JFROG_ARTIFACTORY, OCI. |

### core-create-appsec-policy

***
Creates a new AppSec policy in Cortex Platform with defined conditions, scope, and triggers for application security governance.

#### Base Command

`core-create-appsec-policy`

#### Input

| **Argument Name**                          | **Description**                                                                                                                                                                                                                                                      | **Required** |
|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| policy_name                                | A unique name for the AppSec policy. Must be descriptive and follow organizational naming conventions.                                                                                                                                                               | Required     |
| description                                | A detailed explanation of the policy's objective, use case, and expected outcomes.                                                                                                                                                                                   | Optional     |
| asset_group_names                          | Comma-separated list of Asset Group names to apply the policy to. Asset groups will be automatically resolved to their corresponding IDs.                                                                                                                            | Optional     |
| conditions_finding_type                    | Filter by specific finding types to target policy enforcement. Supported values: Vulnerabilities, IaC Misconfiguration, Licenses, Operational Risk, Secrets, Code Weaknesses, CI/CD Risks.                                                                           | Optional     |
| conditions_severity                        | Filter findings by severity level to prioritize policy actions. Supported values: CRITICAL, HIGH, MEDIUM, LOW.                                                                                                                                                       | Optional     |
| conditions_respect_developer_suppression   | Controls whether a developer’s manual suppression should be honored. Set to 'true' to respect developer suppression (evaluate only non-suppressed findings). Set to 'false' to ignore suppression and always evaluate the finding. Possible values are: true, false. | Optional     |
| conditions_backlog_status                  | Filter findings based on their backlog workflow status (NEW or BACKLOG). Possible values are: NEW, BACKLOG.                                                                                                                                                          | Optional     |
| conditions_package_name                    | Target specific software packages by name for license or vulnerability policies.                                                                                                                                                                                     | Optional     |
| conditions_package_version                 | Specify software package version constraints for precise policy targeting.                                                                                                                                                                                           | Optional     |
| conditions_package_operational_risk        | Filter packages by their operational risk assessment level. Supported values: HIGH, MEDIUM, LOW.                                                                                                                                                                     | Optional     |
| conditions_appsec_rule_names               | Comma-separated list of AppSec rule names to include in policy evaluation. Rule names will be automatically resolved to their corresponding IDs.                                                                                                                     | Optional     |
| conditions_cvss                            | CVSS base score threshold for vulnerability findings (0.0-10.0). Only vulnerabilities meeting or exceeding this score will trigger the policy.                                                                                                                       | Optional     |
| conditions_epss                            | Exploit Prediction Scoring System score threshold (0-100). Targets vulnerabilities with higher exploitation probability.                                                                                                                                             | Optional     |
| conditions_has_a_fix                       | Filter findings based on whether a remediation fix or patch is available. Possible values are: true, false.                                                                                                                                                          | Optional     |
| conditions_is_kev                          | Target findings listed in CISA's Known Exploited Vulnerabilities (KEV) catalog for prioritized remediation. Possible values are: true, false.                                                                                                                        | Optional     |
| conditions_secret_validity                 | Filter exposed secrets by their validity status. Supported values: VALID (active secrets), PRIVILEGED (high-access secrets), INVALID (expired/revoked), UNAVAILABLE (status unknown).                                                                                | Optional     |
| conditions_license_type                    | Target specific software license types for compliance and legal risk management.                                                                                                                                                                                     | Optional     |
| scope_category                             | Define asset categories to include in policy scope. Supported values: Application, Repository, CI/CD Instance, CI/CD Pipeline, VCS Collaborator, VCS Organization.                                                                                                   | Optional     |
| scope_business_application_names           | Target specific business applications by name for focused policy enforcement.                                                                                                                                                                                        | Optional     |
| scope_application_business_criticality     | Filter applications by business criticality level. Supported values: CRITICAL, HIGH, MEDIUM, LOW.                                                                                                                                                                    | Optional     |
| scope_repository_name                      | Target specific code repositories by name for repository-focused policies.                                                                                                                                                                                           | Optional     |
| scope_is_public_repository                 | Filter repositories based on their visibility (public vs private) for exposure risk management. Possible values are: true, false.                                                                                                                                    | Optional     |
| scope_has_deployed_assets                  | Target repositories or applications that have associated deployed infrastructure or runtime assets. Possible values are: true, false.                                                                                                                                | Optional     |
| scope_has_internet_exposed_deployed_assets | Filter assets based on whether the deployed components are exposed to internet traffic for external attack surface management. Possible values are: true, false.                                                                                                     | Optional     |
| scope_has_sensitive_data_access            | Target deployed assets that have access to sensitive data stores, databases, or classified information. Possible values are: true, false.                                                                                                                            | Optional     |
| scope_has_privileged_capabilities          | Filter deployed assets with elevated privileges, admin access, or high-impact system capabilities. Possible values are: true, false.                                                                                                                                 | Optional     |
| triggers_periodic_report_issue             | Enables detection during scheduled scans. When a violation is found in a periodic scan, an issue will be created ("Detect"). Possible values are: true, false.                                                                                                       | Optional     |
| triggers_periodic_override_severity        | Override the default severity level for issues created by periodic scan detections. Possible values are: Critical, High, Medium, Low.                                                                                                                                | Optional     |
| triggers_pr_report_issue                   | Enables detection during pull request scans. When a violation is found in a PR, an issue is created. Required for PR-based detection. Possible values are: true, false.                                                                                              | Optional     |
| triggers_pr_block_pr                       | Blocks merging of pull requests that contain violations detected by the policy. Possible values are: true, false.                                                                                                                                                    | Optional     |
| triggers_pr_report_pr_comment              | Adds an automated comment to pull requests summarizing detected violations and guidance. Possible values are: true, false.                                                                                                                                           | Optional     |
| triggers_pr_override_severity              | Override the default severity level for issues created by pull request detections. Possible values are: Critical, High, Medium, Low.                                                                                                                                 | Optional     |
| triggers_cicd_report_issue                 | Enables detection during CI/CD pipeline scans. When a violation is found in a pipeline run, an issue is created. Possible values are: true, false.                                                                                                                   | Optional     |
| triggers_cicd_block_cicd                   | Blocks or fails CI/CD pipeline runs when violations occur. Possible values are: true, false.                                                                                                                                                                         | Optional     |
| triggers_cicd_report_cicd                  | Reports violation details back to the CI/CD system (pipeline logs, dashboards, status checks). Possible values are: true, false.                                                                                                                                     | Optional     |
| triggers_cicd_override_severity            | Override the default severity level for issues created by CI/CD pipeline detections. Possible values are: Critical, High, Medium, Low.                                                                                                                               | Optional     |

#### Context Output

There is no context output for this command.

### core-update-issue

***
Updates the properties of an issue. This command does not provide an explicit indication of success.

#### Base Command

`core-update-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Issue ID to update. If empty, updates the current issue ID. | Optional |
| assigned_user_mail | Email address of the user to assign the issue to. | Optional |
| severity | Change the severity of an issue. Possible values are: low, medium, high, critical. | Optional |
| name | Change the issue name. | Optional |
| occurred | Change the occurred time of an issue. Supports different time formats, for example: 3 days ago, 2017-09-27T10:00:00+03:00. | Optional |
| phase | Change the phase of an issue. Possible values are: Triage, Investigation, Containment, Response. | Optional |
| type | Change the type of an issue. | Optional |
| description | Change the description of an issue. | Optional |
| status | Change the status of an issue. Possible values are: New, In Progress, Resolved - Known Issue, Resolved - Duplicate Issue, Resolved - False Positive, Resolved - other, Resolved - True Positive, Resolved - Security Testing, Resolved - Dismissed, Resolved - Fixed, Resolved - Risk Accepted. | Optional |

#### Context Output

There is no context output for this command.

### core-appsec-remediate-issue

***
Create automated pull requests to fix multiple security issues in a single bulk operation.

#### Base Command

`core-appsec-remediate-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_ids | A comma-separated list of issue IDs to fix (maximum 10 per request). | Required |
| title | Custom title for the pull request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.TriggeredPRs.issueId | String | The issue identifier. |
| Core.TriggeredPRs.status | String | Either "triggered" or "automated_fix_not_available". |

### core-get-appsec-issues

***
Retrieves application security issues based on specified filters.

#### Base Command

`core-get-appsec-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of issues to return. Default is 50. | Optional |
| sort_field | The field by which to sort the results. Default is severity. | Optional |
| sort_order | The order in which to sort the results. Possible values are: DESC, ASC. Default is DESC. | Optional |
| start_time | The start time for filtering according to issue insert time. Supports free-text relative and absolute times. For example: 7 days ago, 2023-06-15T10:30:00Z, 13/8/2025. | Optional |
| end_time | The end time for filtering according to issue insert time. Supports free-text relative and absolute times. For example: 7 days ago, 2023-06-15T10:30:00Z, 13/8/2025. | Optional |
| issue_id | The issue ID. Accepts a comma-separated list. | Optional |
| assignee | The email of the user assigned to the issue. Accepts a comma-separated list. <br/>Use 'unassigned' for all unassigned issues or 'assigned' for all assigned issues.<br/>. | Optional |
| collaborator | The collaborators of the issue. Accepts a comma-separated list. | Optional |
| status | The issue status. Accepts a comma-separated list. Possible values are: New, In Progress, Resolved. | Optional |
| issue_name | The issue name. Accepts a comma-separated list. | Optional |
| asset_name | The name of the affected asset for the issue. Accepts a comma-separated list. | Optional |
| repository | The repository of the issue. Accepts a comma-separated list. | Optional |
| file_path | The path of the relevant file for the issue. Accepts a comma-separated list. | Optional |
| backlog_status | The backlog status of the issue. Accepts a comma-separated list. Possible values are: BACKLOG, NEW. | Optional |
| cvss_score_gte | The minimum CVSS score. | Optional |
| epss_score_gte | The minimum EPSS score. | Optional |
| has_kev | Filter by vulnerabilities that have a Known Exploited Vulnerability (KEV). Possible values are: true, false. | Optional |
| severity | The severity of the issue. Accepts a comma-separated list. Possible values are: info, low, medium, high, critical. | Optional |
| urgency | The urgency of the issue. Accepts a comma-separated list. Possible values are: N/A, NOT_URGENT, URGENT, TOP_URGENT. | Optional |
| automated_fix_available | Is there an available automated fix. Possible values are: true, false. | Optional |
| sla | SLA status of the issue. Accepts a comma-separated list. Possible values are: Approaching, On Track, Overdue. | Optional |
| validation | Validation status of the issue. Accepts a comma-separated list. Possible values are: INVALID, NO_VALIDATION, PRIVILEGED, UNAVAILABLE, VALID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.AppsecIssue.internal_id | String | The unique identifier for the issue. |
| Core.AppsecIssue.asset_name | String | The names of the assets related to the issue. |
| Core.AppsecIssue.severity | String | The severity of the issue. |
| Core.AppsecIssue.epss_score | Number | The Exploit Prediction Scoring System \(EPSS\) score. |
| Core.AppsecIssue.cvss_score | Number | The Common Vulnerability Scoring System \(CVSS\) score. |
| Core.AppsecIssue.assignee | String | The full name of the user assigned to the issue. |
| Core.AppsecIssue.is_fixable | Boolean | Whether a fix is available for the issue. |
| Core.AppsecIssue.issue_name | String | The name of the issue. |
| Core.AppsecIssue.issue_source | String | The source of the issue. |
| Core.AppsecIssue.issue_category | String | The category of the issue. |
| Core.AppsecIssue.issue_domain | String | The domain of the issue. |
| Core.AppsecIssue.issue_description | String | The description of the issue. |
| Core.AppsecIssue.status | String | The status of the issue. |
| Core.AppsecIssue.time_added | Number | The timestamp when the issue was inserted. |
| Core.AppsecIssue.urgency | String | The urgency of the issue. |
| Core.AppsecIssue.sla_status | String | The SLA status of the issue. |
| Core.AppsecIssue.secret_validation | String | The secret validation status of the issue. |
| Core.AppsecIssue.repository_name | String | The name of the repository where the issue was found. |
| Core.AppsecIssue.repository_organization | String | The organization of the repository where the issue was found. |
| Core.AppsecIssue.file_path | String | The file path related to the issue. |
| Core.AppsecIssue.collaborator | String | The collaborator associated with the issue. |
| Core.AppsecIssue.has_kev | Boolean | Whether the issue is part of the Known Exploited Vulnerabilities catalog \(KEV\). |
| Core.AppsecIssue.backlog_status | String | The backlog status of the issue. |

<!--
### core-list-endpoints

***
Retrieves endpoints based on the provided filters.

#### Base Command

`core-list-endpoints`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_name | A comma-separated list of endpoint names. | Optional |
| endpoint_type | A comma-separated list of endpoint types. Possible values are: mobile, server, workstation, containerized, serverless. | Optional |
| endpoint_status | A comma-separated list of endpoint connection statuses. Possible values are: connected, lost, disconnected, uninstalled, vdi pending login, forensics offline. | Optional |
| platform | A comma-separated list of endpoint platforms. Possible values are: windows, mac, linux, android, ios, serverless. | Optional |
| operating_system | A comma-separated list of operating system names (e.g., Windows, macOS, Linux). | Optional |
| agent_version | A comma-separated list of agent versions (e.g., 8.9.0.14028). | Optional |
| agent_eol | Indicates whether the endpoint is running an End-of-Life (EOL) agent version. Possible values are: true, false. | Optional |
| os_version | A comma-separated list of OS versions (e.g., 10.0.22621). | Optional |
| ip_address | A comma-separated list of endpoint IP addresses. | Optional |
| domain | A comma-separated list of domains. | Optional |
| assigned_prevention_policy | A comma-separated list of assigned prevention policies. Possible values are: pcastro, Caas Default, kris, democloud, Linux Default, Android Default, Serverless Function Default, macOS Default, iOS Default, Windows Default, bcpolicy. | Optional |
| group_name | A comma-separated list of group names assigned to the endpoints. | Optional |
| tags | A comma-separated list of endpoint tags. | Optional |
| endpoint_id | A comma-separated list of endpoint IDs. | Optional |
| operational_status | A comma-separated list of endpoint operational protection statuses. Possible values are: protected, partially protected, unprotected. | Optional |
| cloud_provider | A comma-separated list of cloud providers. Possible values are: aws, azure, gcp, alibaba, oracle, on_prem. | Optional |
| cloud_region | A comma-separated list of cloud regions. | Optional |
| page | Page number for pagination. Default is 0. Default is 0. | Optional |
| limit | Maximum number of results per page. Default and maximum is 100. Default is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Endpoint.endpoint_name | String | The endpoint name. |
| Core.Endpoint.endpoint_type | String | The endpoint type. |
| Core.Endpoint.endpoint_status | String | The endpoint status. |
| Core.Endpoint.platform | String | The endpoint platform. |
| Core.Endpoint.operating_system | String | The operating system of the endpoint. |
| Core.Endpoint.agent_version | String | The agent version installed on the endpoint. |
| Core.Endpoint.agent_eol | String | Is agent EOL. |
| Core.Endpoint.os_version | String | The operating system version. |
| Core.Endpoint.ip_address | String | The endpoint IP address. |
| Core.Endpoint.domain | String | The domain of the endpoint. |
| Core.Endpoint.assigned_prevention_policy | String | The assigned prevention policy. |
| Core.Endpoint.group_name | List | A list of group names the endpoint belongs to. |
| Core.Endpoint.tags | List | A list of tags assigned to the endpoint. |
| Core.Endpoint.endpoint_id | String | The unique endpoint ID. |
| Core.Endpoint.operational_status | String | The operational status of the endpoint. |
| Core.Endpoint.cloud_provider | String | The cloud provider associated with the endpoint. |
| Core.Endpoint.cloud_region | String | The cloud region of the endpoint. |
-->