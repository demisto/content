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
| Core.CoreAsset.xdm__cloud__region | unknown | The cloud region where the asset resides. |
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
            "xdm__cloud__region": "Global",
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

>| asset_hierarchy | xdm__asset__type__category | xdm__cloud__region | xdm__asset__module_unstructured_fields | xdm__asset__source | xdm__asset__id | xdm__asset__type__class | xdm__asset__normalized_fields | xdm__asset__first_observed | xdm__asset__last_observed | xdm__asset__name |
xdm__asset__type__name | xdm__asset__strong_id |
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
| custom_filter | A custom filter. When using this argument, other filter arguments are not relevant. example: <br/>`{<br/>                "OR": [<br/>                    {<br/>                        "SEARCH_FIELD": "actor_process_command_line",<br/>                        "SEARCH_TYPE": "EQ",<br/>                        "SEARCH_VALUE": "path_to_file"<br/>                    }<br/>                ]<br/>            }`. | Optional |
| Identity_type | Account type. Accepts a comma-separated list. Possible values are: ANONYMOUS, APPLICATION, COMPUTE, FEDERATED_IDENTITY, SERVICE, SERVICE_ACCOUNT, TEMPORARY_CREDENTIALS, TOKEN, UNKNOWN, USER. | Optional |
| agent_id | A unique identifier per agent. Accepts a comma-separated list. | Optional |
| action_external_hostname | The hostname to connect to. In case of a proxy connection, this value will differ from action_remote_ip. Accepts a comma-separated list. | Optional |
| rule_id | A string identifying the user rule. Accepts a comma-separated list. | Optional |
| rule_name | The name of the user rule. Accepts a comma-separated list. | Optional |
| issue_name | The issue name. Accepts a comma-separated list. | Optional |
| issue_source | The issue source. Accepts a comma-separated list. Possible values are: XDR Agent, XDR Analytics, XDR Analytics BIOC, PAN NGFW, XDR BIOC, XDR IOC, Threat Intelligence, XDR Managed Threat Hunting, Correlation, Prisma Cloud, Prisma Cloud Compute, ASM, IoT Security, Custom Alert, Health, SaaS Attachments, Attack Path, Cloud Network Analyzer, IaC Scanner, CAS Secret Scanner, CI/CD Risks, CLI Scanner, CIEM Scanner, API Traffic Monitor, API Posture Scanner, Agentless Disk Scanner, Kubernetes Scanner, Compute Policy, CSPM Scanner, CAS CVE Scanner, CAS License Scanner, Secrets Scanner, SAST Scanner, Data Policy, Attack Surface Test, Package Operational Risk, Vulnerability Policy, AI Security Posture. | Optional |
| time_frame | Supports relative times or "custom" time option. If you choose the "custom" option, you should use start_time and end_time arguments. Possible values are: 60 minutes, 3 hours, 12 hours, 24 hours, 2 days, 7 days, 14 days, 30 days, custom. | Optional |
| user_name | The name assigned to the user_id during agent runtime. Accepts a comma-separated list. | Optional |
| actor_process_image_name | The file name of the binary file. Accepts a comma-separated list. | Optional |
| causality_actor_process_image_command_line | CGO CMD. Accepts a comma-separated list. | Optional |
| actor_process_image_command_line | Trimmed to 128 unicode chars during event serialization.<br/>Full value reported as part of the original process event. Accepts a comma-separated list. | Optional |
| action_process_image_command_line | The command line of the process created. Accepts a comma-separated list. | Optional |
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
| action_local_port | The local IP address for the connection. Accepts a comma-separated list. | Optional |
| action_remote_port | The remote port for the connection. Accepts a comma-separated list. | Optional |
| dst_action_external_hostname | The hostname connected to. In case of a proxy connection, this value will differ from action_remote_ip. Accepts a comma-separated list. | Optional |
| sort_field | The field by which to sort the results. Default is source_insert_ts. | Optional |
| sort_order | The order in which to sort the results. Possible values are: DESC, ASC. | Optional |
| offset | The first page from which we bring the issues. Default is 0. | Optional |
| limit | The last page from which we bring the issues. Default is 50. | Optional |
| start_time | Relevant when "time_frame" argument is "custom". Supports epoch timestamp and simplified extended ISO format (YYYY-MM-DDThh:mm:ss). | Optional |
| end_time | Relevant when "time_frame" argument is "custom". Supports epoch timestamp and simplified extended ISO format (YYYY-MM-DDThh:mm:ss). | Optional |
| starred | Whether the issue is starred or not. Possible values are: true, false. | Optional |
| mitre_technique_id_and_name | The MITRE attack technique. Accepts a comma-separated list. | Optional |
| issue_category | The category of the issue. Accepts a comma-separated list. | Optional |
| issue_domain | The domain of the issue. Accepts a comma-separated list. Possible values are: Health, Hunting, IT, Posture, Security. | Optional |
| issue_description | The description of the issue. Accepts a comma-separated list. | Optional |
| os_actor_process_image_sha256 | The SHA256 hash of the OS actor process image. Accepts a comma-separated list. | Optional |
| action_file_macro_sha256 | The SHA256 hash of the action file macro. Accepts a comma-separated list. | Optional |
| status | The status progress. Accepts a comma-separated list. Possible values are: New, In Progress, Resolved. | Optional |
| not_status | Not status progress. Accepts a comma-separated list. Possible values are: New, In Progress, Resolved. | Optional |
| asset_ids | The assets ids related to the issue. Accepts a comma-separated list. | Optional |
| assignee | The assignee of the issue. Accepts a comma-separated list. | Optional |
| output_keys | A comma separated list of outputs to include in the context. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Issue.internal_id | String | The unique ID of the issue. |
| Core.Issue.source_insert_ts | Number | The detection timestamp. |
| Core.Issue.alert_name | String | The name of the issue. |
| Core.Issue.severity | String | The severity of the issue. |
| Core.Issue.alert_category | String | The category of the issue. |
| Core.Issue.alert_action_status | String | The issue action. Possible values.

DETECTED: detected
DETECTED_0: detected \(allowed the session\)
DOWNLOAD: detected \(download\)
DETECTED_19: detected \(forward\)
POST_DETECTED: detected \(post detected\)
PROMPT_ALLOW: detected \(prompt allow\)
DETECTED_4: detected \(raised an issue\)
REPORTED: detected \(reported\)
REPORTED_TRIGGER_4: detected \(on write\)
SCANNED: detected \(scanned\)
DETECTED_23: detected \(sinkhole\)
DETECTED_18: detected \(syncookie sent\)
DETECTED_21: detected \(wildfire upload failure\)
DETECTED_20: detected \(wildfire upload success\)
DETECTED_22: detected \(wildfire upload skip\)
DETECTED_MTH: detected \(xdr managed threat hunting\)
BLOCKED_25: prevented \(block\)
BLOCKED: prevented \(blocked\)
BLOCKED_14: prevented \(block-override\)
BLOCKED_5: prevented \(blocked the url\)
BLOCKED_6: prevented \(blocked the ip\)
BLOCKED_13: prevented \(continue\)
BLOCKED_1: prevented \(denied the session\)
BLOCKED_8: prevented \(dropped all packets\)
BLOCKED_2: prevented \(dropped the session\)
BLOCKED_3: prevented \(dropped the session and sent a tcp reset\)
BLOCKED_7: prevented \(dropped the packet\)
BLOCKED_16: prevented \(override\)
BLOCKED_15: prevented \(override-lockout\)
BLOCKED_26: prevented \(post detected\)
PROMPT_BLOCK: prevented \(prompt block\)
BLOCKED_17: prevented \(random-drop\)
BLOCKED_24: prevented \(silently dropped the session with an icmp unreachable message to the host or application\)
BLOCKED_9: prevented \(terminated the session and sent a tcp reset to both sides of the connection\)
BLOCKED_10: prevented \(terminated the session and sent a tcp reset to the client\)
BLOCKED_11: prevented \(terminated the session and sent a tcp reset to the server\)
BLOCKED_TRIGGER_4: prevented \(on write\). |
| Core.Issue.alert_action_status_readable | String | The issue action. |
| Core.Issue.alert_name | String | The issue name. |
| Core.Issue.alert_description | String | The issue description. |
| Core.Issue.agent_ip_addresses | String | The host IP address. |
| Core.Issue.agent_hostname | String | The hostname. |
| Core.Issue.mitre_tactic_id_and_name | String | The MITRE attack tactic. |
| Core.Issue.mitre_technique_id_and_name | String | The MITRE attack technique. |
| Core.Issue.starred | Boolean | Whether the issue is starred or not. |
