Fetches DLP incidents from the Cyberhaven data security platform and enables investigation of events and data lineage.
This integration was integrated and tested with version 2 of Cyberhaven API.

## Configure Cyberhaven in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., <https://example.cyberhaven.io>) | URL of the Cyberhaven tenant. | True |
| Refresh Token | Provide the Refresh Token for authentication. | True |
| Fetch incidents | Whether to fetch DLP incidents as XSOAR Incidents. | False |
| Incident type | Select Incident type as "Cyberhaven Incident". | False |
| First fetch time | The date or relative timestamp from which to begin fetching DLP Incidents. Default value is '3 days'. The maximum is '30 days'.<br/><br/>If the value is greater than '30 days', it will be considered as '30 days'.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 01 May 2026 04:45:33, 2026-05-17T14:05:44Z. | False |
| Max Fetch | The maximum number of DLP Incidents to fetch each time. Default value is 100. The maximum is 200.<br/><br/>If the value is greater than 200, it will be considered as 200. | False |
| Status of incidents to fetch | Filter the DLP incidents by Status. Default value is 'Open'. | False |
| Severity of incidents to fetch | Filter the DLP incidents by Severity. Default value is 'Informational, Low, Medium, High, Critical'. | False |
| Enable Outgoing Mirroring (from XSOAR to Cyberhaven) | When enabled, updates to the following fields in XSOAR are synchronized to Cyberhaven: Status, Owner, Close Reason, and Close Notes. | False |
| Incidents Fetch Interval | The interval in minutes to fetch incidents. The default is 5 minute. | False |
| Trust any certificate (not secure) | Whether to allow connections without verifying SSL certificates validity. | False |
| Use system proxy settings | Whether to use XSOAR's system proxy settings to connect to the API. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberhaven-incident-list

***
List and search Cyberhaven DLP incidents with optional filters.

#### Base Command

`cyberhaven-incident-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Max incidents to return. Default is 25. | Optional |
| start_time | Filter the incidents by start on or after the provided time. Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| end_time | Filter the incidents by end on or before the provided time. Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| severity | A comma-separated list of severity by which to filter the incidents. Possible values are: Informational, Low, Medium, High, Critical. | Optional |
| status | A comma-separated list of status by which to filter the incidents. Possible values are: Open, Closed. | Optional |
| assignee | Filter the incidents by assigned analyst email. | Optional |
| user | Filter the incidents by user who triggered the incident. | Optional |
| incident_ids | A comma-separated list of incident IDs to filter the results. | Optional |
| page_id | Page ID to retrieve the next set of the incidents. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberhaven.Incident.id | String | The unique identifier of the incident. |
| Cyberhaven.Incident.user.id | String | The identifier of the user who triggered the incident. |
| Cyberhaven.Incident.user.local_username | String | The local machine username of the user who triggered the incident. |
| Cyberhaven.Incident.user.local_id | String | The local identifier of the user who triggered the incident. |
| Cyberhaven.Incident.event_lineage_id.start_event_id | String | The ID of the first event in the lineage chain. |
| Cyberhaven.Incident.event_lineage_id.end_event_id | String | The ID of the last event in the lineage chain. |
| Cyberhaven.Incident.blocked | Boolean | Whether the action that triggered the incident was blocked. |
| Cyberhaven.Incident.event_time | Date | The timestamp of the event that triggered the incident. |
| Cyberhaven.Incident.trigger_time | Date | The timestamp when the incident was triggered. |
| Cyberhaven.Incident.dataset.id | String | The identifier of the dataset involved in the incident. |
| Cyberhaven.Incident.dataset.name | String | The name of the dataset involved in the incident. |
| Cyberhaven.Incident.dataset.sensitivity | String | The sensitivity classification of the dataset involved. |
| Cyberhaven.Incident.user_risk_groups | String | The list of risk groups the user belongs to. |
| Cyberhaven.Incident.policy.id | String | The identifier of the DLP policy that was triggered. |
| Cyberhaven.Incident.policy.name | String | The name of the DLP policy that was triggered. |
| Cyberhaven.Incident.policy.severity | String | The severity level defined in the triggering DLP policy. |
| Cyberhaven.Incident.risk_score | Number | The numeric risk score assigned to the incident. |
| Cyberhaven.Incident.screenshot_guid | String | The GUID of the screenshot associated with the incident. |
| Cyberhaven.Incident.warning_status | String | The warning acknowledgement status of the incident. |
| Cyberhaven.Incident.user_reactions | String | The list of user reaction codes for the incident. |
| Cyberhaven.Incident.user_reaction_message | String | The message provided by the user when reacting to the warning. |
| Cyberhaven.Incident.reaction_time | Date | The timestamp when the user reacted to the warning. |
| Cyberhaven.Incident.assigned_to | String | The email of the analyst the incident is assigned to. |
| Cyberhaven.Incident.status | String | The current status of the incident \(e.g. open, closed\). |
| Cyberhaven.Incident.resolution_time | Date | The timestamp when the incident was resolved. |
| Cyberhaven.Incident.close_reason | String | The reason code provided when the incident was closed. |
| Cyberhaven.Incident.close_note | String | The free-text note provided when the incident was closed. |
| Cyberhaven.Incident.created_by | String | Indicates how the incident was created \(e.g. created_by_policy\). |
| Cyberhaven.Incident.ai_summary | String | The AI-generated summary of the incident. |
| Cyberhaven.Incident.ai_severity | String | The AI-assessed severity level of the incident. |
| Cyberhaven.Incident.last_modified | Date | The timestamp when the incident was last modified. |
| Cyberhaven.Incident.event_details.start_event.id | String | The ID of the start event. |
| Cyberhaven.Incident.event_details.start_event.timestamp | Date | The timestamp of the start event. |
| Cyberhaven.Incident.event_details.start_event.action.kind | String | The action kind performed in the start event \(e.g. copy\). |
| Cyberhaven.Incident.event_details.start_event.action.blocked | Boolean | Whether the action in the start event was blocked. |
| Cyberhaven.Incident.event_details.start_event.action.data_size | Number | The size of data involved in the start event action \(bytes\). |
| Cyberhaven.Incident.event_details.start_event.action.content.tags | String | The content classification tags detected in the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.content.attributes | String | The content attributes of the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.content.upload_filename | String | The filename of the content being uploaded in the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.content.inspected | Boolean | Whether the content was inspected in the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.sensor_kind | String | The sensor type that detected the start event \(e.g. endpoint\). |
| Cyberhaven.Incident.event_details.start_event.action.hostname | String | The hostname of the machine where the start event occurred. |
| Cyberhaven.Incident.event_details.start_event.action.machine_serial_number | String | The serial number of the machine where the start event occurred. |
| Cyberhaven.Incident.event_details.start_event.action.ip_address | String | The IP address of the machine where the start event occurred. |
| Cyberhaven.Incident.event_details.start_event.action.device_type | String | The device management type for the start event \(e.g. managed\). |
| Cyberhaven.Incident.event_details.start_event.action.temporary_blocked | Boolean | Whether the start event action was temporarily blocked. |
| Cyberhaven.Incident.event_details.start_event.action.fail_close_statuses | String | The list of fail-close status objects for the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.process_id | Number | The process ID of the process that triggered the start event. |
| Cyberhaven.Incident.event_details.start_event.action.parent_process_id | Number | The parent process ID of the process that triggered the start event. |
| Cyberhaven.Incident.event_details.start_event.user.id | String | The identifier of the user in the start event. |
| Cyberhaven.Incident.event_details.start_event.user.local_username | String | The local username of the user in the start event. |
| Cyberhaven.Incident.event_details.start_event.user.local_id | String | The local ID of the user in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.id | String | The ID of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.display_name | String | The display name of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.datastore_id | String | The datastore ID associated with the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.dataset_sensitivity | String | The sensitivity classification of the dataset in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.dataset_ids | String | The list of dataset IDs associated with the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.object_type | String | The object type \(e.g. file, removable_storage\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.state | String | The state of the object \(e.g. active\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.content.tags | String | The content classification tags in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.content.attributes | String | The content attributes in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.content.upload_filename | String | The upload filename of the content in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.content.inspected | Boolean | Whether the content was inspected in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.data.labels | String | The data classification labels in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.data.label_ids | String | The data classification label IDs in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.name | String | The name of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.description | String | The description of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.package_name | String | The package name of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.binary_path | String | The binary path of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.command_line | String | The command line of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.main_window_title | String | The main window title of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.name | String | The file name in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.extension | String | The file extension in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.size | Number | The file size \(bytes\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.md5_hash | String | The MD5 hash of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.sha256_hash | String | The SHA-256 hash of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.created_at | Date | The creation timestamp of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.modified_at | Date | The last modification timestamp of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.owner.name | String | The name of the file owner in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.owner.id | String | The ID of the file owner in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.local_file.id | String | The local file ID in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.local_file.path | String | The local file system path in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.network_share.hostname | String | The hostname of the network share in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.network_share.path | String | The path of the network share in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.id | String | The ID of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.from | String | The sender of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.to | String | The recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.cc | String | The CC recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.bcc | String | The BCC recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.subject | String | The subject of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email_attachment.id | String | The ID of the email attachment in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.url | String | The URL of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.domain | String | The domain of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.category | String | The category of the web endpoint \(e.g. cloud_storage\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.download_url | String | The download URL of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.title | String | The page title of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.user_agent | String | The user-agent string of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.provider | String | The cloud provider \(e.g. google\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.name | String | The name of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.user_name | String | The username in the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.user_email | String | The user email in the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.instance_id | String | The instance ID of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.instance_name | String | The instance name of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_file.id | String | The ID of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_file.content_uri | String | The content URI of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_file.path | String | The path of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_share_recipient.scope | String | The sharing scope in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_share_recipient.role | String | The role of the cloud share recipient in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.name | String | The name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.description | String | The description of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.physical_location | String | The physical location of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.server | String | The print server hostname in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.share_name | String | The share name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.port | String | The port of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.driver | String | The driver name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.is_local | Boolean | Whether the printer is local in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.job_id | String | The print job ID in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.connectivity | String | The connectivity type of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.id | String | The ID of the removable storage device in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.name | String | The name of the removable storage device in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.vendor_id | String | The USB vendor ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.product_id | String | The USB product ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.sender | String | The sender of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.recipient_users | String | The recipient users of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.recipient_groups | String | The recipient groups of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.domain | String | The domain of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.workspace | String | The workspace of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.source_code_repo.organization | String | The organization of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.source_code_repo.name | String | The name of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.source_code_repo.branch | String | The branch of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.source_code_repo.id | String | The ID of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.labels | String | The labels applied to the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.label_ids | String | The label IDs applied to the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.matched_policies | String | The list of DLP policies matched by the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.issues | String | The list of DLP issues detected on the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.outline | String | The outline description of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.type | String | The endpoint type \(e.g. endpoint, removable_media\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.domain | String | The domain of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.discovered_at | Date | The timestamp when the object was first discovered in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.updated_at | Date | The timestamp when the object was last updated in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.id | String | The ID of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.action_kind | String | The action kind of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.timestamp | Date | The timestamp of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.user.id | String | The user ID in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.user.local_username | String | The local username in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.user.local_id | String | The local ID in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.version_id | String | The version ID of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.id | String | The ID of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.type | String | The type of cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.name | String | The name of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.account_id | String | The account ID of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.id | String | The ID of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.display_name | String | The display name of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.datastore_id | String | The datastore ID associated with the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.dataset_sensitivity | String | The sensitivity classification of the dataset in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.dataset_ids | String | The list of dataset IDs associated with the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.object_type | String | The object type \(e.g. file, removable_storage\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.state | String | The state of the object \(e.g. active\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.content.tags | String | The content classification tags in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.content.attributes | String | The content attributes in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.content.upload_filename | String | The upload filename of the content in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.content.inspected | Boolean | Whether the content was inspected in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.data.labels | String | The data classification labels in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.data.label_ids | String | The data classification label IDs in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.name | String | The name of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.description | String | The description of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.package_name | String | The package name of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.binary_path | String | The binary path of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.command_line | String | The command line of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.main_window_title | String | The main window title of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.name | String | The file name in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.extension | String | The file extension in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.size | Number | The file size \(bytes\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.md5_hash | String | The MD5 hash of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.sha256_hash | String | The SHA-256 hash of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.created_at | Date | The creation timestamp of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.modified_at | Date | The last modification timestamp of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.owner.name | String | The name of the file owner in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.owner.id | String | The ID of the file owner in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.local_file.id | String | The local file ID in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.local_file.path | String | The local file system path in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.network_share.hostname | String | The hostname of the network share in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.network_share.path | String | The path of the network share in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.id | String | The ID of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.from | String | The sender of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.to | String | The recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.cc | String | The CC recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.bcc | String | The BCC recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.subject | String | The subject of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email_attachment.id | String | The ID of the email attachment in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.url | String | The URL of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.domain | String | The domain of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.category | String | The category of the web endpoint \(e.g. cloud_storage\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.download_url | String | The download URL of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.title | String | The page title of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.user_agent | String | The user-agent string of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.provider | String | The cloud provider \(e.g. google\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.name | String | The name of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.user_name | String | The username in the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.user_email | String | The user email in the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.instance_id | String | The instance ID of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.instance_name | String | The instance name of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_file.id | String | The ID of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_file.content_uri | String | The content URI of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_file.path | String | The path of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_share_recipient.scope | String | The sharing scope in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_share_recipient.role | String | The role of the cloud share recipient in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.name | String | The name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.description | String | The description of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.physical_location | String | The physical location of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.server | String | The print server hostname in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.share_name | String | The share name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.port | String | The port of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.driver | String | The driver name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.is_local | Boolean | Whether the printer is local in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.job_id | String | The print job ID in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.connectivity | String | The connectivity type of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.id | String | The ID of the removable storage device in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.name | String | The name of the removable storage device in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.vendor_id | String | The USB vendor ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.product_id | String | The USB product ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.sender | String | The sender of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.recipient_users | String | The recipient users of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.recipient_groups | String | The recipient groups of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.domain | String | The domain of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.workspace | String | The workspace of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.source_code_repo.organization | String | The organization of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.source_code_repo.name | String | The name of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.source_code_repo.branch | String | The branch of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.source_code_repo.id | String | The ID of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.labels | String | The labels applied to the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.label_ids | String | The label IDs applied to the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.matched_policies | String | The list of DLP policies matched by the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.issues | String | The list of DLP issues detected on the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.outline | String | The outline description of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.type | String | The endpoint type \(e.g. endpoint, removable_media\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.domain | String | The domain of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.discovered_at | Date | The timestamp when the object was first discovered in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.updated_at | Date | The timestamp when the object was last updated in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.id | String | The ID of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.action_kind | String | The action kind of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.timestamp | Date | The timestamp of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.user.id | String | The user ID in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.user.local_username | String | The local username in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.user.local_id | String | The local ID in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.version_id | String | The version ID of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.id | String | The ID of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.type | String | The type of cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.name | String | The name of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.account_id | String | The account ID of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.end_event.id | String | The ID of the end event. |
| Cyberhaven.Incident.event_details.end_event.timestamp | Date | The timestamp of the end event. |
| Cyberhaven.Incident.event_details.end_event.action.kind | String | The action kind performed in the end event \(e.g. copy\). |
| Cyberhaven.Incident.event_details.end_event.action.blocked | Boolean | Whether the action in the end event was blocked. |
| Cyberhaven.Incident.event_details.end_event.action.data_size | Number | The size of data involved in the end event action \(bytes\). |
| Cyberhaven.Incident.event_details.end_event.action.content.tags | String | The content classification tags detected in the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.content.attributes | String | The content attributes of the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.content.upload_filename | String | The filename of the content being uploaded in the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.content.inspected | Boolean | Whether the content was inspected in the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.sensor_kind | String | The sensor type that detected the end event \(e.g. endpoint\). |
| Cyberhaven.Incident.event_details.end_event.action.hostname | String | The hostname of the machine where the end event occurred. |
| Cyberhaven.Incident.event_details.end_event.action.machine_serial_number | String | The serial number of the machine where the end event occurred. |
| Cyberhaven.Incident.event_details.end_event.action.ip_address | String | The IP address of the machine where the end event occurred. |
| Cyberhaven.Incident.event_details.end_event.action.device_type | String | The device management type for the end event \(e.g. managed\). |
| Cyberhaven.Incident.event_details.end_event.action.temporary_blocked | Boolean | Whether the end event action was temporarily blocked. |
| Cyberhaven.Incident.event_details.end_event.action.fail_close_statuses | String | The list of fail-close status objects for the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.process_id | Number | The process ID of the process that triggered the end event. |
| Cyberhaven.Incident.event_details.end_event.action.parent_process_id | Number | The parent process ID of the process that triggered the end event. |
| Cyberhaven.Incident.event_details.end_event.user.id | String | The identifier of the user in the end event. |
| Cyberhaven.Incident.event_details.end_event.user.local_username | String | The local username of the user in the end event. |
| Cyberhaven.Incident.event_details.end_event.user.local_id | String | The local ID of the user in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.id | String | The ID of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.display_name | String | The display name of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.datastore_id | String | The datastore ID associated with the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.dataset_sensitivity | String | The sensitivity classification of the dataset in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.dataset_ids | String | The list of dataset IDs associated with the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.object_type | String | The object type \(e.g. file, removable_storage\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.state | String | The state of the object \(e.g. active\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.content.tags | String | The content classification tags in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.content.attributes | String | The content attributes in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.content.upload_filename | String | The upload filename of the content in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.content.inspected | Boolean | Whether the content was inspected in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.data.labels | String | The data classification labels in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.data.label_ids | String | The data classification label IDs in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.name | String | The name of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.description | String | The description of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.package_name | String | The package name of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.binary_path | String | The binary path of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.command_line | String | The command line of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.main_window_title | String | The main window title of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.name | String | The file name in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.extension | String | The file extension in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.size | Number | The file size \(bytes\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.md5_hash | String | The MD5 hash of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.sha256_hash | String | The SHA-256 hash of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.created_at | Date | The creation timestamp of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.modified_at | Date | The last modification timestamp of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.owner.name | String | The name of the file owner in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.owner.id | String | The ID of the file owner in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.local_file.id | String | The local file ID in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.local_file.path | String | The local file system path in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.network_share.hostname | String | The hostname of the network share in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.network_share.path | String | The path of the network share in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.id | String | The ID of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.from | String | The sender of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.to | String | The recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.cc | String | The CC recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.bcc | String | The BCC recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.subject | String | The subject of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email_attachment.id | String | The ID of the email attachment in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.url | String | The URL of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.domain | String | The domain of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.category | String | The category of the web endpoint \(e.g. cloud_storage\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.download_url | String | The download URL of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.title | String | The page title of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.user_agent | String | The user-agent string of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.provider | String | The cloud provider \(e.g. google\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.name | String | The name of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.user_name | String | The username in the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.user_email | String | The user email in the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.instance_id | String | The instance ID of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.instance_name | String | The instance name of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_file.id | String | The ID of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_file.content_uri | String | The content URI of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_file.path | String | The path of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_share_recipient.scope | String | The sharing scope in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_share_recipient.role | String | The role of the cloud share recipient in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.name | String | The name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.description | String | The description of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.physical_location | String | The physical location of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.server | String | The print server hostname in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.share_name | String | The share name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.port | String | The port of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.driver | String | The driver name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.is_local | Boolean | Whether the printer is local in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.job_id | String | The print job ID in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.connectivity | String | The connectivity type of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.id | String | The ID of the removable storage device in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.name | String | The name of the removable storage device in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.vendor_id | String | The USB vendor ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.product_id | String | The USB product ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.sender | String | The sender of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.recipient_users | String | The recipient users of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.recipient_groups | String | The recipient groups of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.domain | String | The domain of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.workspace | String | The workspace of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.source_code_repo.organization | String | The organization of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.source_code_repo.name | String | The name of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.source_code_repo.branch | String | The branch of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.source_code_repo.id | String | The ID of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.labels | String | The labels applied to the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.label_ids | String | The label IDs applied to the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.matched_policies | String | The list of DLP policies matched by the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.issues | String | The list of DLP issues detected on the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.outline | String | The outline description of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.type | String | The endpoint type \(e.g. endpoint, removable_media\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.domain | String | The domain of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.discovered_at | Date | The timestamp when the object was first discovered in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.updated_at | Date | The timestamp when the object was last updated in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.id | String | The ID of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.action_kind | String | The action kind of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.timestamp | Date | The timestamp of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.user.id | String | The user ID in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.user.local_username | String | The local username in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.user.local_id | String | The local ID in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.version_id | String | The version ID of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.id | String | The ID of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.type | String | The type of cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.name | String | The name of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.account_id | String | The account ID of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.id | String | The ID of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.display_name | String | The display name of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.datastore_id | String | The datastore ID associated with the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.dataset_sensitivity | String | The sensitivity classification of the dataset in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.dataset_ids | String | The list of dataset IDs associated with the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.object_type | String | The object type \(e.g. file, removable_storage\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.state | String | The state of the object \(e.g. active\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.content.tags | String | The content classification tags in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.content.attributes | String | The content attributes in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.content.upload_filename | String | The upload filename of the content in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.content.inspected | Boolean | Whether the content was inspected in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.data.labels | String | The data classification labels in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.data.label_ids | String | The data classification label IDs in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.name | String | The name of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.description | String | The description of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.package_name | String | The package name of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.binary_path | String | The binary path of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.command_line | String | The command line of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.main_window_title | String | The main window title of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.name | String | The file name in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.extension | String | The file extension in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.size | Number | The file size \(bytes\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.md5_hash | String | The MD5 hash of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.sha256_hash | String | The SHA-256 hash of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.created_at | Date | The creation timestamp of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.modified_at | Date | The last modification timestamp of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.owner.name | String | The name of the file owner in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.owner.id | String | The ID of the file owner in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.local_file.id | String | The local file ID in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.local_file.path | String | The local file system path in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.network_share.hostname | String | The hostname of the network share in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.network_share.path | String | The path of the network share in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.id | String | The ID of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.from | String | The sender of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.to | String | The recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.cc | String | The CC recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.bcc | String | The BCC recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.subject | String | The subject of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email_attachment.id | String | The ID of the email attachment in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.url | String | The URL of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.domain | String | The domain of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.category | String | The category of the web endpoint \(e.g. cloud_storage\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.download_url | String | The download URL of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.title | String | The page title of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.user_agent | String | The user-agent string of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.provider | String | The cloud provider \(e.g. google\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.name | String | The name of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.user_name | String | The username in the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.user_email | String | The user email in the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.instance_id | String | The instance ID of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.instance_name | String | The instance name of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_file.id | String | The ID of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_file.content_uri | String | The content URI of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_file.path | String | The path of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_share_recipient.scope | String | The sharing scope in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_share_recipient.role | String | The role of the cloud share recipient in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.name | String | The name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.description | String | The description of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.physical_location | String | The physical location of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.server | String | The print server hostname in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.share_name | String | The share name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.port | String | The port of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.driver | String | The driver name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.is_local | Boolean | Whether the printer is local in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.job_id | String | The print job ID in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.connectivity | String | The connectivity type of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.id | String | The ID of the removable storage device in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.name | String | The name of the removable storage device in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.vendor_id | String | The USB vendor ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.product_id | String | The USB product ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.sender | String | The sender of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.recipient_users | String | The recipient users of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.recipient_groups | String | The recipient groups of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.domain | String | The domain of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.workspace | String | The workspace of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.source_code_repo.organization | String | The organization of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.source_code_repo.name | String | The name of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.source_code_repo.branch | String | The branch of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.source_code_repo.id | String | The ID of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.labels | String | The labels applied to the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.label_ids | String | The label IDs applied to the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.matched_policies | String | The list of DLP policies matched by the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.issues | String | The list of DLP issues detected on the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.outline | String | The outline description of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.type | String | The endpoint type \(e.g. endpoint, removable_media\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.domain | String | The domain of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.discovered_at | Date | The timestamp when the object was first discovered in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.updated_at | Date | The timestamp when the object was last updated in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.id | String | The ID of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.action_kind | String | The action kind of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.timestamp | Date | The timestamp of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.user.id | String | The user ID in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.user.local_username | String | The local username in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.user.local_id | String | The local ID in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.version_id | String | The version ID of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.id | String | The ID of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.type | String | The type of cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.name | String | The name of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.account_id | String | The account ID of the cloud connector in the end event. |
| Cyberhaven.IncidentPage.next_id | String | The opaque cursor for the next page of results. Pass this value as page_id to retrieve the next page. |
| Cyberhaven.IncidentPage.total | Number | The total number of incidents for the provided filters. |

#### Command example

```!cyberhaven-incident-list limit=2 start_time="3 days"```

#### Context Example

```json
{
    "Cyberhaven": {
        "Incidents": [
            {
                "id": "inc_a1b2c3d4e5f6",
                "user": {
                    "id": "usr_john_doe_001",
                    "local_username": "john.doe",
                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                    "custom_data": {
                        "department": "Engineering",
                        "manager_email": "jane.smith@company.com",
                        "employee_id": "EMP-10042",
                        "location": "US-NYC",
                        "role": "Senior Software Engineer"
                    }
                },
                "event_lineage_id": {
                    "start_event_id": "evt_start_001abc",
                    "end_event_id": "evt_end_002xyz"
                },
                "blocked": false,
                "event_time": "2026-01-15T10:28:45Z",
                "trigger_time": "2026-01-15T10:29:02Z",
                "dataset": {
                    "id": "ds_hr_confidential",
                    "name": "HR Confidential Records",
                    "sensitivity": "high",
                    "custom_data": {
                        "classification_level": "confidential",
                        "data_owner": "hr@company.com"
                    }
                },
                "user_risk_groups": [
                    {
                        "id": "rg_high_risk_users",
                        "name": "High Risk Users",
                        "risk_multiplier": 1.5,
                        "custom_data": {
                            "criteria": "multiple_policy_violations"
                        }
                    }
                ],
                "policy": {
                    "id": "pol_dlp_hr_001",
                    "name": "HR Data Exfiltration Prevention",
                    "severity": "high",
                    "custom_data": {
                        "policy_owner": "security@company.com",
                        "enforcement_mode": "block",
                        "review_cycle": "quarterly",
                        "compliance_framework": "SOC2"
                    }
                },
                "risk_score": 8.5,
                "screenshot_guid": "scrn_7f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
                "warning_status": "warning_shown",
                "user_reactions": [
                    "reaction_acknowledged"
                ],
                "user_reaction_message": "I was transferring files for an approved project backup.",
                "reaction_time": "2026-01-15T10:31:15Z",
                "assigned_to": "analyst@company.com",
                "status": "open",
                "resolution_time": "2026-01-15T14:45:00Z",
                "close_reason": "policy_violation",
                "close_note": "User violated data exfiltration policy. Escalated to HR.",
                "custom_data": {
                    "ticket_id": "JIRA-4521"
                },
                "created_by": "created_by_system",
                "ai_summary": "User john.doe attempted to copy confidential HR records to a removable USB drive. The action was detected by endpoint DLP and flagged as a high-severity policy violation.",
                "ai_severity": "high",
                "last_modified": "2026-01-15T11:00:00Z",
                "event_details": {
                    "start_event": {
                        "id": "evt_start_001abc",
                        "timestamp": "2026-01-15T10:28:45Z",
                        "action": {
                            "kind": "copy",
                            "blocked": false,
                            "data_size": 2048576,
                            "content": {
                                "tags": [
                                    "pii",
                                    "confidential"
                                ],
                                "attributes": {
                                    "word_count": 1500
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "encoding": "UTF-8"
                                },
                                "inspected": true
                            },
                            "sensor_kind": "endpoint",
                            "hostname": "WORKSTATION-NYC-042",
                            "machine_serial_number": "C02XK1JFHV2R",
                            "custom_data": {
                                "os_version": "Windows 11 22H2"
                            },
                            "ip_address": "192.168.1.100",
                            "device_type": "managed",
                            "temporary_blocked": false,
                            "fail_close_statuses": [
                                {
                                    "temporary_blocked": false,
                                    "dlp_api_status": "SUCCESS",
                                    "dlp_precondition": "DLP_PRECONDITION_MET",
                                    "action_status": "ACTION_STATUS_COMPLETED"
                                }
                            ],
                            "process_id": 4821,
                            "parent_process_id": 1024
                        },
                        "user": {
                            "id": "usr_john_doe_001",
                            "local_username": "john.doe",
                            "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                            "custom_data": {
                                "ad_group": "Domain Users",
                                "upn": "john.doe@company.com",
                                "last_login": "2026-01-15T08:05:00Z"
                            }
                        },
                        "source": {
                            "id": "src_local_001abc",
                            "display_name": "employee_salaries_2026.xlsx",
                            "datastore_id": "dstore_endpoint_01",
                            "dataset_sensitivity": "sensitivity_high",
                            "dataset_ids": [
                                "ds_hr_confidential"
                            ],
                            "object_type": "file",
                            "state": "active",
                            "content": {
                                "tags": [
                                    "pii",
                                    "confidential"
                                ],
                                "attributes": {
                                    "record_count": 250
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "classification": "confidential",
                                    "last_scan": "2026-01-10T09:00:00Z",
                                    "scan_result": "contains_pii",
                                    "owner_department": "HR"
                                },
                                "inspected": true
                            },
                            "data": {
                                "labels": [
                                    "PII",
                                    "Confidential",
                                    "HR Data"
                                ],
                                "label_ids": [
                                    "lbl_pii",
                                    "lbl_confidential"
                                ]
                            },
                            "app": {
                                "name": "Microsoft Excel",
                                "description": "Microsoft Office Spreadsheet Application",
                                "package_name": "com.microsoft.excel",
                                "binary_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                                "command_line": "\"EXCEL.EXE\" /e",
                                "main_window_title": "employee_salaries_2026.xlsx - Excel",
                                "custom_data": {
                                    "version": "16.0.17126.20132",
                                    "publisher": "Microsoft Corporation",
                                    "signed": "true",
                                    "install_date": "2023-06-01",
                                    "auto_update": "enabled"
                                }
                            },
                            "file": {
                                "name": "employee_salaries_2026.xlsx",
                                "extension": "xlsx",
                                "size": 2048576,
                                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "custom_data": {
                                    "creator": "john.doe",
                                    "last_modified_by": "jane.smith"
                                },
                                "created_at": "2026-01-10T09:00:00Z",
                                "modified_at": "2026-01-15T08:30:00Z",
                                "owner": {
                                    "name": "john.doe",
                                    "id": "usr_john_doe_001"
                                }
                            },
                            "local_file": {
                                "id": "lf_001abc",
                                "path": "C:\\Users\\john.doe\\Documents\\HR\\employee_salaries_2026.xlsx"
                            },
                            "network_share": {
                                "hostname": "FILESERVER-01",
                                "path": "\\\\FILESERVER-01\\HR\\Compensation",
                                "custom_data": {
                                    "share_type": "SMB"
                                }
                            },
                            "email": {
                                "id": "email_src_001",
                                "from": "john.doe@company.com",
                                "to": [
                                    "personal@gmail.com"
                                ],
                                "cc": [
                                    "backup@gmail.com"
                                ],
                                "bcc": [
                                    "archive@gmail.com"
                                ],
                                "subject": "Salary Data Backup",
                                "custom_data": {
                                    "message_id": "<20260115102845.001@company.com>",
                                    "x_mailer": "Microsoft Outlook 16.0"
                                }
                            },
                            "email_attachment": {
                                "id": "attach_src_001",
                                "custom_data": {
                                    "attachment_index": "0",
                                    "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                }
                            },
                            "web": {
                                "url": "https://drive.google.com/upload",
                                "domain": "drive.google.com",
                                "category": "cloud_storage",
                                "download_url": "https://drive.google.com/file/d/1abc123/view",
                                "title": "Google Drive - Upload",
                                "custom_data": {
                                    "referrer": "https://drive.google.com/",
                                    "request_method": "POST"
                                },
                                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                            },
                            "cloud_app": {
                                "provider": "google",
                                "name": "google_drive",
                                "user_name": "john.doe",
                                "user_email": "john.doe@personal.com",
                                "custom_data": {
                                    "tenant_id": "tenant_google_001",
                                    "app_version": "2026.1"
                                },
                                "instance_id": "gdrive_inst_001",
                                "instance_name": "Personal Google Drive"
                            },
                            "cloud_file": {
                                "id": "cf_src_001",
                                "content_uri": "https://drive.google.com/file/d/1abc123/content",
                                "path": "/My Drive/HR Data/employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "revision_id": "rev_001"
                                }
                            },
                            "cloud_share_recipient": {
                                "scope": "share_external",
                                "user_ids": [
                                    "external_user_001"
                                ],
                                "role": "role_viewer",
                                "custom_data": {
                                    "expiry_date": "2026-12-31",
                                    "notify_on_access": "true"
                                }
                            },
                            "printer": {
                                "name": "HP LaserJet Pro M404n",
                                "description": "Office Laser Printer - Floor 3",
                                "physical_location": "3rd Floor Copy Room",
                                "server": "PRINTSERVER-01",
                                "share_name": "HP-LaserJet-3F",
                                "port": "IP_192.168.1.200",
                                "driver": "HP LaserJet Pro M404n PCL 6",
                                "is_local": false,
                                "job_id": "print_job_4521",
                                "custom_data": {
                                    "pages_printed": "12",
                                    "duplex": "false"
                                },
                                "connectivity": "network"
                            },
                            "removable_storage": {
                                "id": "usb_src_001",
                                "name": "SanDisk Ultra 64GB",
                                "usb_id": "usb_0781_5581",
                                "vendor_id": "0781",
                                "product_id": "5581",
                                "custom_data": {
                                    "serial_number": "4C530001041120115283",
                                    "file_system": "NTFS",
                                    "capacity_gb": "64"
                                }
                            },
                            "im_message": {
                                "sender": "john.doe@company.com",
                                "recipient_users": [
                                    "personal.contact@gmail.com"
                                ],
                                "recipient_groups": [
                                    "external-group-001"
                                ],
                                "domain": "teams.microsoft.com",
                                "workspace": "Personal Chat",
                                "custom_data": {
                                    "message_id": "msg_001abc"
                                }
                            },
                            "source_code_repo": {
                                "organization": "company-org",
                                "name": "hr-data-scripts",
                                "custom_data": {
                                    "visibility": "private",
                                    "default_branch": "main",
                                    "last_commit": "a1b2c3d4e5f6",
                                    "language": "Python"
                                },
                                "branch": "main",
                                "id": "repo_001"
                            },
                            "labels": [
                                "PII",
                                "Confidential"
                            ],
                            "label_ids": [
                                "lbl_pii",
                                "lbl_confidential"
                            ],
                            "matched_policies": [
                                {
                                    "policy_type": "dlp",
                                    "id": "pol_dlp_hr_001",
                                    "version": 3,
                                    "definition_rule_ids": [
                                        "rule_pii_detection",
                                        "rule_confidential_data"
                                    ],
                                    "action_rule_id": "action_rule_block",
                                    "matched_at": "2026-01-15T10:28:45Z"
                                }
                            ],
                            "issues": [
                                {
                                    "id": "issue_001abc",
                                    "policy_type": "dlp",
                                    "matched_policy_id": "pol_dlp_hr_001",
                                    "policy_action_rule_id": "action_rule_block",
                                    "severity": "issue_severity_high",
                                    "detected_at": "2026-01-15T10:28:45Z"
                                }
                            ],
                            "custom_data": {
                                "data_classification": "confidential",
                                "retention_policy": "7_years",
                                "gdpr_relevant": "true",
                                "ccpa_relevant": "true"
                            },
                            "outline": "Spreadsheet containing employee salary and compensation data for 250 employees in the Engineering department.",
                            "type": "removable_media",
                            "domain": "company.com",
                            "discovered_at": "2026-01-10T09:00:00Z",
                            "updated_at": "2026-01-15T10:28:45Z",
                            "update_event": {
                                "id": "upd_evt_001",
                                "action_kind": "copy",
                                "timestamp": "2026-01-15T10:28:45Z",
                                "user": {
                                    "id": "usr_john_doe_001",
                                    "local_username": "john.doe",
                                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                                    "custom_data": {
                                        "session_id": "sess_20260115_001"
                                    }
                                }
                            },
                            "version_id": "ver_001abc",
                            "cloud_connector": {
                                "id": "cc_box_001",
                                "type": "box",
                                "name": "Company Box Integration",
                                "onboarding_account": "admin@company.com",
                                "account_id": "box_acct_001"
                            }
                        },
                        "destination": {
                            "id": "dst_usb_001abc",
                            "display_name": "SanDisk Ultra 64GB (E:)",
                            "datastore_id": "dstore_usb_01",
                            "dataset_sensitivity": "sensitivity_unspecified",
                            "dataset_ids": [
                                "ds_removable_default"
                            ],
                            "object_type": "removable_storage",
                            "state": "active",
                            "content": {
                                "tags": [
                                    "external",
                                    "removable"
                                ],
                                "attributes": {
                                    "file_count": 1,
                                    "total_size": 2048576
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "destination_path": "E:\\Backup\\HR",
                                    "overwrite": "false"
                                },
                                "inspected": true
                            },
                            "data": {
                                "labels": [
                                    "External Storage"
                                ],
                                "label_ids": [
                                    "lbl_external_storage"
                                ]
                            },
                            "app": {
                                "name": "Windows Explorer",
                                "description": "Windows File Explorer",
                                "package_name": "com.microsoft.explorer",
                                "binary_path": "C:\\Windows\\explorer.exe",
                                "command_line": "explorer.exe /select,\"E:\\Backup\\HR\\employee_salaries_2026.xlsx\"",
                                "main_window_title": "E:\\Backup\\HR",
                                "custom_data": {
                                    "version": "10.0.22621.1"
                                }
                            },
                            "file": {
                                "name": "employee_salaries_2026.xlsx",
                                "extension": "xlsx",
                                "size": 2048576,
                                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "custom_data": {
                                    "destination_created": "true",
                                    "is_copy": "true",
                                    "original_path": "C:\\Users\\john.doe\\Documents\\HR\\employee_salaries_2026.xlsx"
                                },
                                "created_at": "2026-01-15T10:28:50Z",
                                "modified_at": "2026-01-15T10:28:50Z",
                                "owner": {
                                    "name": "john.doe",
                                    "id": "usr_john_doe_001"
                                }
                            },
                            "local_file": {
                                "id": "lf_dst_001",
                                "path": "E:\\Backup\\HR\\employee_salaries_2026.xlsx"
                            },
                            "network_share": {
                                "hostname": "FILESERVER-01",
                                "path": "\\\\FILESERVER-01\\Backup\\HR",
                                "custom_data": {
                                    "share_type": "SMB"
                                }
                            },
                            "email": {
                                "id": "email_dst_001",
                                "from": "john.doe@company.com",
                                "to": [
                                    "personal@gmail.com"
                                ],
                                "cc": [
                                    "backup@gmail.com"
                                ],
                                "bcc": [
                                    "archive@gmail.com"
                                ],
                                "subject": "Salary Data Backup",
                                "custom_data": {
                                    "message_id": "<20260115102845.001@company.com>"
                                }
                            },
                            "email_attachment": {
                                "id": "attach_dst_001",
                                "custom_data": {
                                    "attachment_index": "0",
                                    "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "file_size": "2048576",
                                    "sanitized": "false"
                                }
                            },
                            "web": {
                                "url": "https://drive.google.com/upload/resumable",
                                "domain": "drive.google.com",
                                "category": "cloud_storage",
                                "download_url": "https://drive.google.com/file/d/1abc123/view",
                                "title": "Google Drive - Upload Complete",
                                "custom_data": {
                                    "upload_session_id": "upload_sess_001"
                                },
                                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                            },
                            "cloud_app": {
                                "provider": "google",
                                "name": "google_drive",
                                "user_name": "john.doe",
                                "user_email": "john.doe@personal.com",
                                "custom_data": {
                                    "upload_complete": "true"
                                },
                                "instance_id": "gdrive_inst_001",
                                "instance_name": "Personal Google Drive"
                            },
                            "cloud_file": {
                                "id": "cf_dst_001",
                                "content_uri": "https://drive.google.com/file/d/1abc123/content",
                                "path": "/My Drive/HR Backup/employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "upload_timestamp": "2026-01-15T10:29:00Z",
                                    "file_id": "1abc123xyz"
                                }
                            },
                            "cloud_share_recipient": {
                                "scope": "share_external",
                                "user_ids": [
                                    "external_user_001",
                                    "external_user_002"
                                ],
                                "role": "role_viewer",
                                "custom_data": {
                                    "expiry_date": "2026-12-31",
                                    "notify_on_access": "true",
                                    "link_type": "restricted"
                                }
                            },
                            "printer": {
                                "name": "HP LaserJet Pro M404n",
                                "description": "Office Laser Printer - Floor 3",
                                "physical_location": "3rd Floor Copy Room",
                                "server": "PRINTSERVER-01",
                                "share_name": "HP-LaserJet-3F",
                                "port": "IP_192.168.1.200",
                                "driver": "HP LaserJet Pro M404n PCL 6",
                                "is_local": false,
                                "job_id": "print_job_4521",
                                "custom_data": {
                                    "pages_printed": "12"
                                },
                                "connectivity": "network"
                            },
                            "removable_storage": {
                                "id": "usb_dst_001",
                                "name": "SanDisk Ultra 64GB",
                                "usb_id": "usb_0781_5581",
                                "vendor_id": "0781",
                                "product_id": "5581",
                                "custom_data": {
                                    "serial_number": "4C530001041120115283",
                                    "drive_letter": "E",
                                    "free_space_gb": "45"
                                }
                            },
                            "im_message": {
                                "sender": "john.doe@company.com",
                                "recipient_users": [
                                    "personal.contact@gmail.com"
                                ],
                                "recipient_groups": [
                                    "external-group-001"
                                ],
                                "domain": "teams.microsoft.com",
                                "workspace": "Personal Chat",
                                "custom_data": {
                                    "message_id": "msg_dst_001",
                                    "channel": "direct",
                                    "platform": "teams",
                                    "thread_id": "thread_001",
                                    "is_external": "true"
                                }
                            },
                            "source_code_repo": {
                                "organization": "personal-org",
                                "name": "personal-backup-repo",
                                "custom_data": {
                                    "visibility": "private"
                                },
                                "branch": "main",
                                "id": "repo_dst_001"
                            },
                            "labels": [
                                "External Storage",
                                "Removable Media"
                            ],
                            "label_ids": [
                                "lbl_external_storage",
                                "lbl_removable_media"
                            ],
                            "matched_policies": [
                                {
                                    "policy_type": "dlp",
                                    "id": "pol_dlp_removable_001",
                                    "version": 2,
                                    "definition_rule_ids": [
                                        "rule_removable_media_write"
                                    ],
                                    "action_rule_id": "action_rule_alert",
                                    "matched_at": "2026-01-15T10:28:50Z"
                                }
                            ],
                            "issues": [
                                {
                                    "id": "issue_dst_001",
                                    "policy_type": "dlp",
                                    "matched_policy_id": "pol_dlp_removable_001",
                                    "policy_action_rule_id": "action_rule_alert",
                                    "severity": "issue_severity_high",
                                    "detected_at": "2026-01-15T10:28:50Z"
                                }
                            ],
                            "custom_data": {
                                "endpoint_risk": "high",
                                "device_approved": "false"
                            },
                            "outline": "USB removable storage device used as destination for confidential HR file transfer.",
                            "type": "share",
                            "domain": "company.com",
                            "discovered_at": "2026-01-15T10:28:45Z",
                            "updated_at": "2026-01-15T10:28:50Z",
                            "update_event": {
                                "id": "upd_evt_dst_001",
                                "action_kind": "write",
                                "timestamp": "2026-01-15T10:28:50Z",
                                "user": {
                                    "id": "usr_john_doe_001",
                                    "local_username": "john.doe",
                                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                                    "custom_data": {
                                        "session_id": "sess_20260115_001"
                                    }
                                }
                            },
                            "version_id": "ver_dst_001",
                            "cloud_connector": {
                                "id": "cc_gcs_001",
                                "type": "gcs",
                                "name": "Company GCS Integration",
                                "onboarding_account": "gcs-service@company.iam.gserviceaccount.com",
                                "account_id": "gcs_acct_001"
                            }
                        }
                    },
                    "end_event": {
                        "id": "evt_end_002xyz",
                        "timestamp": "2026-01-15T10:29:00Z",
                        "action": {
                            "kind": "upload",
                            "blocked": false,
                            "data_size": 2048576,
                            "content": {
                                "tags": [
                                    "pii",
                                    "confidential"
                                ],
                                "attributes": {
                                    "word_count": 1500,
                                    "page_count": 3
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "encoding": "UTF-8",
                                    "compressed": "false",
                                    "checksum_verified": "true"
                                },
                                "inspected": true
                            },
                            "sensor_kind": "endpoint",
                            "hostname": "WORKSTATION-NYC-042",
                            "machine_serial_number": "C02XK1JFHV2R",
                            "custom_data": {
                                "os_version": "Windows 11 22H2",
                                "network_zone": "internal"
                            },
                            "ip_address": "192.168.1.100",
                            "device_type": "managed",
                            "temporary_blocked": false,
                            "fail_close_statuses": [
                                {
                                    "temporary_blocked": false,
                                    "dlp_api_status": "SUCCESS",
                                    "dlp_precondition": "DLP_PRECONDITION_MET",
                                    "action_status": "ACTION_STATUS_COMPLETED"
                                }
                            ],
                            "process_id": 4821,
                            "parent_process_id": 1024
                        },
                        "user": {
                            "id": "usr_john_doe_001",
                            "local_username": "john.doe",
                            "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                            "custom_data": {
                                "session_id": "sess_20260115_001"
                            }
                        },
                        "source": {
                            "id": "src_end_001abc",
                            "display_name": "E:\\Backup\\HR\\employee_salaries_2026.xlsx",
                            "datastore_id": "dstore_usb_01",
                            "dataset_sensitivity": "sensitivity_unspecified",
                            "dataset_ids": [
                                "ds_removable_default"
                            ],
                            "object_type": "file",
                            "state": "active",
                            "content": {
                                "tags": [
                                    "pii",
                                    "confidential"
                                ],
                                "attributes": {
                                    "record_count": 250
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "path": "E:\\Backup\\HR\\employee_salaries_2026.xlsx"
                                },
                                "inspected": true
                            },
                            "data": {
                                "labels": [
                                    "PII",
                                    "Confidential"
                                ],
                                "label_ids": [
                                    "lbl_pii",
                                    "lbl_confidential"
                                ]
                            },
                            "app": {
                                "name": "Windows Explorer",
                                "description": "Windows File Explorer",
                                "package_name": "com.microsoft.explorer",
                                "binary_path": "C:\\Windows\\explorer.exe",
                                "command_line": "explorer.exe",
                                "main_window_title": "E:\\Backup\\HR",
                                "custom_data": {
                                    "version": "10.0.22621.1"
                                }
                            },
                            "file": {
                                "name": "employee_salaries_2026.xlsx",
                                "extension": "xlsx",
                                "size": 2048576,
                                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "custom_data": {
                                    "drive_letter": "E"
                                },
                                "created_at": "2026-01-15T10:28:50Z",
                                "modified_at": "2026-01-15T10:28:50Z",
                                "owner": {
                                    "name": "john.doe",
                                    "id": "usr_john_doe_001"
                                }
                            },
                            "local_file": {
                                "id": "lf_end_src_001",
                                "path": "E:\\Backup\\HR\\employee_salaries_2026.xlsx"
                            },
                            "network_share": {
                                "hostname": "FILESERVER-01",
                                "path": "\\\\FILESERVER-01\\HR\\Compensation",
                                "custom_data": {
                                    "share_type": "SMB",
                                    "mount_point": "Z:"
                                }
                            },
                            "email": {
                                "id": "email_end_src_001",
                                "from": "john.doe@company.com",
                                "to": [
                                    "personal@gmail.com"
                                ],
                                "cc": [
                                    "backup@gmail.com"
                                ],
                                "bcc": [
                                    "archive@gmail.com"
                                ],
                                "subject": "Salary Data Backup",
                                "custom_data": {
                                    "message_id": "<20260115102900.002@company.com>"
                                }
                            },
                            "email_attachment": {
                                "id": "attach_end_src_001",
                                "custom_data": {
                                    "attachment_index": "0"
                                }
                            },
                            "web": {
                                "url": "https://drive.google.com/upload",
                                "domain": "drive.google.com",
                                "category": "cloud_storage",
                                "download_url": "https://drive.google.com/file/d/1abc123/view",
                                "title": "Google Drive",
                                "custom_data": {
                                    "referrer": "https://drive.google.com/",
                                    "request_method": "POST",
                                    "response_code": "200"
                                },
                                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                            },
                            "cloud_app": {
                                "provider": "google",
                                "name": "google_drive",
                                "user_name": "john.doe",
                                "user_email": "john.doe@personal.com",
                                "custom_data": {
                                    "tenant_id": "tenant_google_001",
                                    "app_version": "2026.1",
                                    "auth_method": "oauth2"
                                },
                                "instance_id": "gdrive_inst_001",
                                "instance_name": "Personal Google Drive"
                            },
                            "cloud_file": {
                                "id": "cf_end_src_001",
                                "content_uri": "https://drive.google.com/file/d/1abc123/content",
                                "path": "/My Drive/HR Backup/employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "file_id": "1abc123xyz",
                                    "revision": "1"
                                }
                            },
                            "cloud_share_recipient": {
                                "scope": "share_external",
                                "user_ids": [
                                    "external_user_001"
                                ],
                                "role": "role_viewer",
                                "custom_data": {
                                    "expiry_date": "2026-12-31"
                                }
                            },
                            "printer": {
                                "name": "HP LaserJet Pro M404n",
                                "description": "Office Laser Printer - Floor 3",
                                "physical_location": "3rd Floor Copy Room",
                                "server": "PRINTSERVER-01",
                                "share_name": "HP-LaserJet-3F",
                                "port": "IP_192.168.1.200",
                                "driver": "HP LaserJet Pro M404n PCL 6",
                                "is_local": false,
                                "job_id": "print_job_4522",
                                "custom_data": {
                                    "pages_printed": "12"
                                },
                                "connectivity": "network"
                            },
                            "removable_storage": {
                                "id": "usb_end_src_001",
                                "name": "SanDisk Ultra 64GB",
                                "usb_id": "usb_0781_5581",
                                "vendor_id": "0781",
                                "product_id": "5581",
                                "custom_data": {
                                    "serial_number": "4C530001041120115283",
                                    "file_system": "NTFS",
                                    "drive_letter": "E"
                                }
                            },
                            "im_message": {
                                "sender": "john.doe@company.com",
                                "recipient_users": [
                                    "personal.contact@gmail.com"
                                ],
                                "recipient_groups": [
                                    "external-group-001"
                                ],
                                "domain": "teams.microsoft.com",
                                "workspace": "Personal Chat",
                                "custom_data": {
                                    "message_id": "msg_end_001",
                                    "platform": "teams",
                                    "thread_id": "thread_001",
                                    "channel_type": "direct_message"
                                }
                            },
                            "source_code_repo": {
                                "organization": "company-org",
                                "name": "hr-data-scripts",
                                "custom_data": {
                                    "visibility": "private"
                                },
                                "branch": "main",
                                "id": "repo_end_src_001"
                            },
                            "labels": [
                                "External Storage",
                                "PII"
                            ],
                            "label_ids": [
                                "lbl_external_storage",
                                "lbl_pii"
                            ],
                            "matched_policies": [
                                {
                                    "policy_type": "dlp",
                                    "id": "pol_dlp_hr_001",
                                    "version": 3,
                                    "definition_rule_ids": [
                                        "rule_pii_detection"
                                    ],
                                    "action_rule_id": "action_rule_block",
                                    "matched_at": "2026-01-15T10:29:00Z"
                                }
                            ],
                            "issues": [
                                {
                                    "id": "issue_end_src_001",
                                    "policy_type": "dlp",
                                    "matched_policy_id": "pol_dlp_hr_001",
                                    "policy_action_rule_id": "action_rule_block",
                                    "severity": "issue_severity_high",
                                    "detected_at": "2026-01-15T10:29:00Z"
                                }
                            ],
                            "custom_data": {
                                "data_classification": "confidential",
                                "risk_level": "high",
                                "source_type": "removable_media"
                            },
                            "outline": "File read from USB removable storage during end event of the data transfer sequence.",
                            "type": "endpoint",
                            "domain": "company.com",
                            "discovered_at": "2026-01-15T10:28:50Z",
                            "updated_at": "2026-01-15T10:29:00Z",
                            "update_event": {
                                "id": "upd_evt_end_src_001",
                                "action_kind": "read",
                                "timestamp": "2026-01-15T10:29:00Z",
                                "user": {
                                    "id": "usr_john_doe_001",
                                    "local_username": "john.doe",
                                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                                    "custom_data": {
                                        "session_id": "sess_20260115_001"
                                    }
                                }
                            },
                            "version_id": "ver_end_src_001",
                            "cloud_connector": {
                                "id": "cc_salesforce_001",
                                "type": "salesforce",
                                "name": "Company Salesforce Integration",
                                "onboarding_account": "admin@company.com",
                                "account_id": "sf_acct_001"
                            }
                        },
                        "destination": {
                            "id": "dst_end_001abc",
                            "display_name": "Google Drive - Personal",
                            "datastore_id": "dstore_gdrive_01",
                            "dataset_sensitivity": "sensitivity_unspecified",
                            "dataset_ids": [
                                "ds_external_cloud"
                            ],
                            "object_type": "cloud_file",
                            "state": "active",
                            "content": {
                                "tags": [
                                    "external",
                                    "cloud"
                                ],
                                "attributes": {
                                    "file_count": 1,
                                    "total_size": 2048576,
                                    "upload_chunks": 2,
                                    "retry_count": 0,
                                    "transfer_duration_ms": 1250
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "upload_method": "resumable",
                                    "destination_folder": "/My Drive/HR Backup",
                                    "overwrite_existing": "false"
                                },
                                "inspected": true
                            },
                            "data": {
                                "labels": [
                                    "External",
                                    "Cloud Storage"
                                ],
                                "label_ids": [
                                    "lbl_external",
                                    "lbl_cloud_storage"
                                ]
                            },
                            "app": {
                                "name": "Google Chrome",
                                "description": "Google Chrome Web Browser",
                                "package_name": "com.google.chrome",
                                "binary_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                "command_line": "chrome.exe --profile-directory=Default",
                                "main_window_title": "Google Drive - Google Chrome",
                                "custom_data": {
                                    "version": "120.0.6099.130",
                                    "profile": "Default"
                                }
                            },
                            "file": {
                                "name": "employee_salaries_2026.xlsx",
                                "extension": "xlsx",
                                "size": 2048576,
                                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "custom_data": {
                                    "cloud_file_id": "1abc123xyz",
                                    "upload_session": "upload_sess_001"
                                },
                                "created_at": "2026-01-15T10:29:05Z",
                                "modified_at": "2026-01-15T10:29:05Z",
                                "owner": {
                                    "name": "john.doe",
                                    "id": "usr_john_doe_001"
                                }
                            },
                            "local_file": {
                                "id": "lf_end_dst_001",
                                "path": "C:\\Users\\john.doe\\Downloads\\employee_salaries_2026.xlsx"
                            },
                            "network_share": {
                                "hostname": "EXTERNAL-SHARE-01",
                                "path": "\\\\EXTERNAL-SHARE-01\\Public",
                                "custom_data": {
                                    "share_type": "SMB",
                                    "external_network": "true"
                                }
                            },
                            "email": {
                                "id": "email_end_dst_001",
                                "from": "john.doe@company.com",
                                "to": [
                                    "personal@gmail.com"
                                ],
                                "cc": [
                                    "backup@gmail.com"
                                ],
                                "bcc": [
                                    "archive@gmail.com"
                                ],
                                "subject": "Salary Data Backup",
                                "custom_data": {
                                    "message_id": "<20260115102900.002@company.com>",
                                    "smtp_server": "smtp.gmail.com"
                                }
                            },
                            "email_attachment": {
                                "id": "attach_end_dst_001",
                                "custom_data": {
                                    "attachment_index": "0",
                                    "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "file_size": "2048576",
                                    "sanitized": "false"
                                }
                            },
                            "web": {
                                "url": "https://drive.google.com/file/d/1abc123xyz/view",
                                "domain": "drive.google.com",
                                "category": "cloud_storage",
                                "download_url": "https://drive.google.com/uc?id=1abc123xyz&export=download",
                                "title": "employee_salaries_2026.xlsx - Google Drive",
                                "custom_data": {
                                    "file_id": "1abc123xyz",
                                    "sharing_status": "private"
                                },
                                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                            },
                            "cloud_app": {
                                "provider": "google",
                                "name": "google_drive",
                                "user_name": "john.doe",
                                "user_email": "john.doe@personal.com",
                                "custom_data": {
                                    "account_type": "personal"
                                },
                                "instance_id": "gdrive_inst_001",
                                "instance_name": "Personal Google Drive"
                            },
                            "cloud_file": {
                                "id": "cf_end_dst_001",
                                "content_uri": "https://drive.google.com/file/d/1abc123xyz/content",
                                "path": "/My Drive/HR Backup/employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "file_id": "1abc123xyz",
                                    "revision_id": "rev_001",
                                    "upload_complete": "true"
                                }
                            },
                            "cloud_share_recipient": {
                                "scope": "share_external",
                                "user_ids": [
                                    "external_user_001",
                                    "external_user_002",
                                    "external_user_003"
                                ],
                                "role": "role_editor",
                                "custom_data": {
                                    "expiry_date": "2026-12-31",
                                    "link_type": "restricted",
                                    "notify_on_download": "true"
                                }
                            },
                            "printer": {
                                "name": "HP LaserJet Pro M404n",
                                "description": "Office Laser Printer - Floor 3",
                                "physical_location": "3rd Floor Copy Room",
                                "server": "PRINTSERVER-01",
                                "share_name": "HP-LaserJet-3F",
                                "port": "IP_192.168.1.200",
                                "driver": "HP LaserJet Pro M404n PCL 6",
                                "is_local": false,
                                "job_id": "print_job_4523",
                                "custom_data": {
                                    "pages_printed": "12",
                                    "color": "false"
                                },
                                "connectivity": "network"
                            },
                            "removable_storage": {
                                "id": "usb_end_dst_001",
                                "name": "SanDisk Ultra 64GB",
                                "usb_id": "usb_0781_5581",
                                "vendor_id": "0781",
                                "product_id": "5581",
                                "custom_data": {
                                    "serial_number": "4C530001041120115283"
                                }
                            },
                            "im_message": {
                                "sender": "john.doe@company.com",
                                "recipient_users": [
                                    "personal.contact@gmail.com"
                                ],
                                "recipient_groups": [
                                    "external-group-001"
                                ],
                                "domain": "teams.microsoft.com",
                                "workspace": "Personal Chat",
                                "custom_data": {
                                    "message_id": "msg_end_dst_001"
                                }
                            },
                            "source_code_repo": {
                                "organization": "personal-org",
                                "name": "personal-backup-repo",
                                "custom_data": {
                                    "visibility": "private",
                                    "language": "Python",
                                    "size_kb": "1024"
                                },
                                "branch": "main",
                                "id": "repo_end_dst_001"
                            },
                            "labels": [
                                "External",
                                "Cloud Storage",
                                "Personal Account"
                            ],
                            "label_ids": [
                                "lbl_external",
                                "lbl_cloud_storage"
                            ],
                            "matched_policies": [
                                {
                                    "policy_type": "dlp",
                                    "id": "pol_dlp_cloud_upload_001",
                                    "version": 1,
                                    "definition_rule_ids": [
                                        "rule_cloud_upload_block"
                                    ],
                                    "action_rule_id": "action_rule_block",
                                    "matched_at": "2026-01-15T10:29:00Z"
                                }
                            ],
                            "issues": [
                                {
                                    "id": "issue_end_dst_001",
                                    "policy_type": "dlp",
                                    "matched_policy_id": "pol_dlp_cloud_upload_001",
                                    "policy_action_rule_id": "action_rule_block",
                                    "severity": "issue_severity_high",
                                    "detected_at": "2026-01-15T10:29:00Z"
                                }
                            ],
                            "custom_data": {
                                "upload_destination": "personal_cloud",
                                "risk_level": "critical"
                            },
                            "outline": "Personal Google Drive account used as destination for unauthorized data upload containing HR confidential records.",
                            "type": "removable_media",
                            "domain": "drive.google.com",
                            "discovered_at": "2026-01-15T10:29:00Z",
                            "updated_at": "2026-01-15T10:29:05Z",
                            "update_event": {
                                "id": "upd_evt_end_dst_001",
                                "action_kind": "upload",
                                "timestamp": "2026-01-15T10:29:05Z",
                                "user": {
                                    "id": "usr_john_doe_001",
                                    "local_username": "john.doe",
                                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                                    "custom_data": {
                                        "session_id": "sess_20260115_001"
                                    }
                                }
                            },
                            "version_id": "ver_end_dst_001",
                            "cloud_connector": {
                                "id": "cc_teams_001",
                                "type": "teams",
                                "name": "Company Teams Integration",
                                "onboarding_account": "teams-admin@company.com",
                                "account_id": "teams_acct_001"
                            }
                        }
                    }
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberhaven Incidents
>
>|ID|Policy|Severity|Status|Blocked|Event Time|Start Event ID|End Event ID|AI Summary|
>|---|---|---|---|---|---|---|---|---|
>| [inc_a1b2c3d4e5f6](https://your-tenant.cyberhaven.io/incidents?id=inc_a1b2c3d4e5f6) | HR Data Exfiltration Prevention | high | open | false | 2026-01-15T10:28:45Z | evt_start_001abc | evt_end_002xyz | User john.doe attempted to copy confidential HR records to a removable USB drive. The action was detected by endpoint DLP and flagged as a high-severity policy violation. |

### cyberhaven-incident-update

***
Update the status, assignment, or close reason of a Cyberhaven incident.

#### Base Command

`cyberhaven-incident-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specify the Cyberhaven incident ID.<br/><br/>Note: Use 'cyberhaven-incident-list' to retrieve the incident ID. | Required |
| status | Specify the status of the incident. Possible values are: Open, Closed. | Optional |
| close_reason | Specify the close reason while closing the incident. Possible values are: Resolved, False Positive, False Positive - Destination Not at Risk, False Positive - User Exempt, Other. | Optional |
| close_note | Provide the meaningful note when closing. | Optional |
| assigned_to | Provide analyst email to whom incident will assign. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberhaven.Incident.id | String | The unique identifier of the incident. |
| Cyberhaven.Incident.user.id | String | The identifier of the user who triggered the incident. |
| Cyberhaven.Incident.user.local_username | String | The local machine username of the user who triggered the incident. |
| Cyberhaven.Incident.user.local_id | String | The local identifier of the user who triggered the incident. |
| Cyberhaven.Incident.event_lineage_id.start_event_id | String | The ID of the first event in the lineage chain. |
| Cyberhaven.Incident.event_lineage_id.end_event_id | String | The ID of the last event in the lineage chain. |
| Cyberhaven.Incident.blocked | Boolean | Whether the action that triggered the incident was blocked. |
| Cyberhaven.Incident.event_time | Date | The timestamp of the event that triggered the incident. |
| Cyberhaven.Incident.trigger_time | Date | The timestamp when the incident was triggered. |
| Cyberhaven.Incident.dataset.id | String | The identifier of the dataset involved in the incident. |
| Cyberhaven.Incident.dataset.name | String | The name of the dataset involved in the incident. |
| Cyberhaven.Incident.dataset.sensitivity | String | The sensitivity classification of the dataset involved. |
| Cyberhaven.Incident.user_risk_groups | String | The list of risk groups the user belongs to. |
| Cyberhaven.Incident.policy.id | String | The identifier of the DLP policy that was triggered. |
| Cyberhaven.Incident.policy.name | String | The name of the DLP policy that was triggered. |
| Cyberhaven.Incident.policy.severity | String | The severity level defined in the triggering DLP policy. |
| Cyberhaven.Incident.risk_score | Number | The numeric risk score assigned to the incident. |
| Cyberhaven.Incident.screenshot_guid | String | The GUID of the screenshot associated with the incident. |
| Cyberhaven.Incident.warning_status | String | The warning acknowledgement status of the incident. |
| Cyberhaven.Incident.user_reactions | String | The list of user reaction codes for the incident. |
| Cyberhaven.Incident.user_reaction_message | String | The message provided by the user when reacting to the warning. |
| Cyberhaven.Incident.reaction_time | Date | The timestamp when the user reacted to the warning. |
| Cyberhaven.Incident.assigned_to | String | The email of the analyst the incident is assigned to. |
| Cyberhaven.Incident.status | String | The current status of the incident \(e.g. open, closed\). |
| Cyberhaven.Incident.resolution_time | Date | The timestamp when the incident was resolved. |
| Cyberhaven.Incident.close_reason | String | The reason code provided when the incident was closed. |
| Cyberhaven.Incident.close_note | String | The free-text note provided when the incident was closed. |
| Cyberhaven.Incident.created_by | String | Indicates how the incident was created \(e.g. created_by_policy\). |
| Cyberhaven.Incident.ai_summary | String | The AI-generated summary of the incident. |
| Cyberhaven.Incident.ai_severity | String | The AI-assessed severity level of the incident. |
| Cyberhaven.Incident.last_modified | Date | The timestamp when the incident was last modified. |
| Cyberhaven.Incident.event_details.start_event.id | String | The ID of the start event. |
| Cyberhaven.Incident.event_details.start_event.timestamp | Date | The timestamp of the start event. |
| Cyberhaven.Incident.event_details.start_event.action.kind | String | The action kind performed in the start event \(e.g. copy\). |
| Cyberhaven.Incident.event_details.start_event.action.blocked | Boolean | Whether the action in the start event was blocked. |
| Cyberhaven.Incident.event_details.start_event.action.data_size | Number | The size of data involved in the start event action \(bytes\). |
| Cyberhaven.Incident.event_details.start_event.action.content.tags | String | The content classification tags detected in the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.content.attributes | String | The content attributes of the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.content.upload_filename | String | The filename of the content being uploaded in the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.content.inspected | Boolean | Whether the content was inspected in the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.sensor_kind | String | The sensor type that detected the start event \(e.g. endpoint\). |
| Cyberhaven.Incident.event_details.start_event.action.hostname | String | The hostname of the machine where the start event occurred. |
| Cyberhaven.Incident.event_details.start_event.action.machine_serial_number | String | The serial number of the machine where the start event occurred. |
| Cyberhaven.Incident.event_details.start_event.action.ip_address | String | The IP address of the machine where the start event occurred. |
| Cyberhaven.Incident.event_details.start_event.action.device_type | String | The device management type for the start event \(e.g. managed\). |
| Cyberhaven.Incident.event_details.start_event.action.temporary_blocked | Boolean | Whether the start event action was temporarily blocked. |
| Cyberhaven.Incident.event_details.start_event.action.fail_close_statuses | String | The list of fail-close status objects for the start event action. |
| Cyberhaven.Incident.event_details.start_event.action.process_id | Number | The process ID of the process that triggered the start event. |
| Cyberhaven.Incident.event_details.start_event.action.parent_process_id | Number | The parent process ID of the process that triggered the start event. |
| Cyberhaven.Incident.event_details.start_event.user.id | String | The identifier of the user in the start event. |
| Cyberhaven.Incident.event_details.start_event.user.local_username | String | The local username of the user in the start event. |
| Cyberhaven.Incident.event_details.start_event.user.local_id | String | The local ID of the user in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.id | String | The ID of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.display_name | String | The display name of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.datastore_id | String | The datastore ID associated with the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.dataset_sensitivity | String | The sensitivity classification of the dataset in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.dataset_ids | String | The list of dataset IDs associated with the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.object_type | String | The object type \(e.g. file, removable_storage\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.state | String | The state of the object \(e.g. active\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.content.tags | String | The content classification tags in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.content.attributes | String | The content attributes in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.content.upload_filename | String | The upload filename of the content in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.content.inspected | Boolean | Whether the content was inspected in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.data.labels | String | The data classification labels in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.data.label_ids | String | The data classification label IDs in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.name | String | The name of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.description | String | The description of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.package_name | String | The package name of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.binary_path | String | The binary path of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.command_line | String | The command line of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.app.main_window_title | String | The main window title of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.name | String | The file name in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.extension | String | The file extension in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.size | Number | The file size \(bytes\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.md5_hash | String | The MD5 hash of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.sha256_hash | String | The SHA-256 hash of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.created_at | Date | The creation timestamp of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.modified_at | Date | The last modification timestamp of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.owner.name | String | The name of the file owner in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.file.owner.id | String | The ID of the file owner in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.local_file.id | String | The local file ID in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.local_file.path | String | The local file system path in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.network_share.hostname | String | The hostname of the network share in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.network_share.path | String | The path of the network share in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.id | String | The ID of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.from | String | The sender of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.to | String | The recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.cc | String | The CC recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.bcc | String | The BCC recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email.subject | String | The subject of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.email_attachment.id | String | The ID of the email attachment in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.url | String | The URL of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.domain | String | The domain of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.category | String | The category of the web endpoint \(e.g. cloud_storage\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.download_url | String | The download URL of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.title | String | The page title of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.web.user_agent | String | The user-agent string of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.provider | String | The cloud provider \(e.g. google\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.name | String | The name of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.user_name | String | The username in the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.user_email | String | The user email in the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.instance_id | String | The instance ID of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_app.instance_name | String | The instance name of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_file.id | String | The ID of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_file.content_uri | String | The content URI of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_file.path | String | The path of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_share_recipient.scope | String | The sharing scope in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_share_recipient.role | String | The role of the cloud share recipient in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.name | String | The name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.description | String | The description of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.physical_location | String | The physical location of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.server | String | The print server hostname in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.share_name | String | The share name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.port | String | The port of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.driver | String | The driver name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.is_local | Boolean | Whether the printer is local in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.job_id | String | The print job ID in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.printer.connectivity | String | The connectivity type of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.id | String | The ID of the removable storage device in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.name | String | The name of the removable storage device in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.vendor_id | String | The USB vendor ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.removable_storage.product_id | String | The USB product ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.sender | String | The sender of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.recipient_users | String | The recipient users of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.recipient_groups | String | The recipient groups of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.domain | String | The domain of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.im_message.workspace | String | The workspace of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.source_code_repo.organization | String | The organization of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.source_code_repo.name | String | The name of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.source_code_repo.branch | String | The branch of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.source_code_repo.id | String | The ID of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.labels | String | The labels applied to the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.label_ids | String | The label IDs applied to the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.matched_policies | String | The list of DLP policies matched by the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.issues | String | The list of DLP issues detected on the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.outline | String | The outline description of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.type | String | The endpoint type \(e.g. endpoint, removable_media\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.domain | String | The domain of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.discovered_at | Date | The timestamp when the object was first discovered in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.updated_at | Date | The timestamp when the object was last updated in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.id | String | The ID of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.action_kind | String | The action kind of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.timestamp | Date | The timestamp of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.user.id | String | The user ID in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.user.local_username | String | The local username in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.update_event.user.local_id | String | The local ID in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.version_id | String | The version ID of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.id | String | The ID of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.type | String | The type of cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.name | String | The name of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.source.cloud_connector.account_id | String | The account ID of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.id | String | The ID of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.display_name | String | The display name of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.datastore_id | String | The datastore ID associated with the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.dataset_sensitivity | String | The sensitivity classification of the dataset in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.dataset_ids | String | The list of dataset IDs associated with the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.object_type | String | The object type \(e.g. file, removable_storage\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.state | String | The state of the object \(e.g. active\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.content.tags | String | The content classification tags in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.content.attributes | String | The content attributes in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.content.upload_filename | String | The upload filename of the content in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.content.inspected | Boolean | Whether the content was inspected in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.data.labels | String | The data classification labels in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.data.label_ids | String | The data classification label IDs in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.name | String | The name of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.description | String | The description of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.package_name | String | The package name of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.binary_path | String | The binary path of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.command_line | String | The command line of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.app.main_window_title | String | The main window title of the associated application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.name | String | The file name in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.extension | String | The file extension in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.size | Number | The file size \(bytes\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.md5_hash | String | The MD5 hash of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.sha256_hash | String | The SHA-256 hash of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.created_at | Date | The creation timestamp of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.modified_at | Date | The last modification timestamp of the file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.owner.name | String | The name of the file owner in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.file.owner.id | String | The ID of the file owner in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.local_file.id | String | The local file ID in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.local_file.path | String | The local file system path in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.network_share.hostname | String | The hostname of the network share in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.network_share.path | String | The path of the network share in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.id | String | The ID of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.from | String | The sender of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.to | String | The recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.cc | String | The CC recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.bcc | String | The BCC recipients of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email.subject | String | The subject of the email in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.email_attachment.id | String | The ID of the email attachment in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.url | String | The URL of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.domain | String | The domain of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.category | String | The category of the web endpoint \(e.g. cloud_storage\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.download_url | String | The download URL of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.title | String | The page title of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.web.user_agent | String | The user-agent string of the web endpoint in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.provider | String | The cloud provider \(e.g. google\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.name | String | The name of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.user_name | String | The username in the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.user_email | String | The user email in the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.instance_id | String | The instance ID of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_app.instance_name | String | The instance name of the cloud application in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_file.id | String | The ID of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_file.content_uri | String | The content URI of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_file.path | String | The path of the cloud file in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_share_recipient.scope | String | The sharing scope in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_share_recipient.role | String | The role of the cloud share recipient in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.name | String | The name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.description | String | The description of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.physical_location | String | The physical location of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.server | String | The print server hostname in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.share_name | String | The share name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.port | String | The port of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.driver | String | The driver name of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.is_local | Boolean | Whether the printer is local in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.job_id | String | The print job ID in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.printer.connectivity | String | The connectivity type of the printer in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.id | String | The ID of the removable storage device in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.name | String | The name of the removable storage device in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.vendor_id | String | The USB vendor ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.removable_storage.product_id | String | The USB product ID of the removable storage in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.sender | String | The sender of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.recipient_users | String | The recipient users of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.recipient_groups | String | The recipient groups of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.domain | String | The domain of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.im_message.workspace | String | The workspace of the IM message in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.source_code_repo.organization | String | The organization of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.source_code_repo.name | String | The name of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.source_code_repo.branch | String | The branch of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.source_code_repo.id | String | The ID of the source code repository in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.labels | String | The labels applied to the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.label_ids | String | The label IDs applied to the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.matched_policies | String | The list of DLP policies matched by the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.issues | String | The list of DLP issues detected on the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.outline | String | The outline description of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.type | String | The endpoint type \(e.g. endpoint, removable_media\) in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.domain | String | The domain of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.discovered_at | Date | The timestamp when the object was first discovered in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.updated_at | Date | The timestamp when the object was last updated in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.id | String | The ID of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.action_kind | String | The action kind of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.timestamp | Date | The timestamp of the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.user.id | String | The user ID in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.user.local_username | String | The local username in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.update_event.user.local_id | String | The local ID in the update event in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.version_id | String | The version ID of the object in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.id | String | The ID of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.type | String | The type of cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.name | String | The name of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.start_event.destination.cloud_connector.account_id | String | The account ID of the cloud connector in the start event. |
| Cyberhaven.Incident.event_details.end_event.id | String | The ID of the end event. |
| Cyberhaven.Incident.event_details.end_event.timestamp | Date | The timestamp of the end event. |
| Cyberhaven.Incident.event_details.end_event.action.kind | String | The action kind performed in the end event \(e.g. copy\). |
| Cyberhaven.Incident.event_details.end_event.action.blocked | Boolean | Whether the action in the end event was blocked. |
| Cyberhaven.Incident.event_details.end_event.action.data_size | Number | The size of data involved in the end event action \(bytes\). |
| Cyberhaven.Incident.event_details.end_event.action.content.tags | String | The content classification tags detected in the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.content.attributes | String | The content attributes of the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.content.upload_filename | String | The filename of the content being uploaded in the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.content.inspected | Boolean | Whether the content was inspected in the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.sensor_kind | String | The sensor type that detected the end event \(e.g. endpoint\). |
| Cyberhaven.Incident.event_details.end_event.action.hostname | String | The hostname of the machine where the end event occurred. |
| Cyberhaven.Incident.event_details.end_event.action.machine_serial_number | String | The serial number of the machine where the end event occurred. |
| Cyberhaven.Incident.event_details.end_event.action.ip_address | String | The IP address of the machine where the end event occurred. |
| Cyberhaven.Incident.event_details.end_event.action.device_type | String | The device management type for the end event \(e.g. managed\). |
| Cyberhaven.Incident.event_details.end_event.action.temporary_blocked | Boolean | Whether the end event action was temporarily blocked. |
| Cyberhaven.Incident.event_details.end_event.action.fail_close_statuses | String | The list of fail-close status objects for the end event action. |
| Cyberhaven.Incident.event_details.end_event.action.process_id | Number | The process ID of the process that triggered the end event. |
| Cyberhaven.Incident.event_details.end_event.action.parent_process_id | Number | The parent process ID of the process that triggered the end event. |
| Cyberhaven.Incident.event_details.end_event.user.id | String | The identifier of the user in the end event. |
| Cyberhaven.Incident.event_details.end_event.user.local_username | String | The local username of the user in the end event. |
| Cyberhaven.Incident.event_details.end_event.user.local_id | String | The local ID of the user in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.id | String | The ID of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.display_name | String | The display name of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.datastore_id | String | The datastore ID associated with the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.dataset_sensitivity | String | The sensitivity classification of the dataset in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.dataset_ids | String | The list of dataset IDs associated with the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.object_type | String | The object type \(e.g. file, removable_storage\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.state | String | The state of the object \(e.g. active\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.content.tags | String | The content classification tags in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.content.attributes | String | The content attributes in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.content.upload_filename | String | The upload filename of the content in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.content.inspected | Boolean | Whether the content was inspected in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.data.labels | String | The data classification labels in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.data.label_ids | String | The data classification label IDs in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.name | String | The name of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.description | String | The description of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.package_name | String | The package name of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.binary_path | String | The binary path of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.command_line | String | The command line of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.app.main_window_title | String | The main window title of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.name | String | The file name in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.extension | String | The file extension in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.size | Number | The file size \(bytes\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.md5_hash | String | The MD5 hash of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.sha256_hash | String | The SHA-256 hash of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.created_at | Date | The creation timestamp of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.modified_at | Date | The last modification timestamp of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.owner.name | String | The name of the file owner in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.file.owner.id | String | The ID of the file owner in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.local_file.id | String | The local file ID in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.local_file.path | String | The local file system path in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.network_share.hostname | String | The hostname of the network share in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.network_share.path | String | The path of the network share in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.id | String | The ID of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.from | String | The sender of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.to | String | The recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.cc | String | The CC recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.bcc | String | The BCC recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email.subject | String | The subject of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.email_attachment.id | String | The ID of the email attachment in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.url | String | The URL of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.domain | String | The domain of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.category | String | The category of the web endpoint \(e.g. cloud_storage\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.download_url | String | The download URL of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.title | String | The page title of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.web.user_agent | String | The user-agent string of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.provider | String | The cloud provider \(e.g. google\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.name | String | The name of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.user_name | String | The username in the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.user_email | String | The user email in the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.instance_id | String | The instance ID of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_app.instance_name | String | The instance name of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_file.id | String | The ID of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_file.content_uri | String | The content URI of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_file.path | String | The path of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_share_recipient.scope | String | The sharing scope in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_share_recipient.role | String | The role of the cloud share recipient in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.name | String | The name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.description | String | The description of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.physical_location | String | The physical location of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.server | String | The print server hostname in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.share_name | String | The share name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.port | String | The port of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.driver | String | The driver name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.is_local | Boolean | Whether the printer is local in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.job_id | String | The print job ID in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.printer.connectivity | String | The connectivity type of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.id | String | The ID of the removable storage device in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.name | String | The name of the removable storage device in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.vendor_id | String | The USB vendor ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.removable_storage.product_id | String | The USB product ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.sender | String | The sender of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.recipient_users | String | The recipient users of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.recipient_groups | String | The recipient groups of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.domain | String | The domain of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.im_message.workspace | String | The workspace of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.source_code_repo.organization | String | The organization of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.source_code_repo.name | String | The name of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.source_code_repo.branch | String | The branch of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.source_code_repo.id | String | The ID of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.labels | String | The labels applied to the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.label_ids | String | The label IDs applied to the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.matched_policies | String | The list of DLP policies matched by the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.issues | String | The list of DLP issues detected on the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.outline | String | The outline description of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.type | String | The endpoint type \(e.g. endpoint, removable_media\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.domain | String | The domain of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.discovered_at | Date | The timestamp when the object was first discovered in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.updated_at | Date | The timestamp when the object was last updated in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.id | String | The ID of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.action_kind | String | The action kind of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.timestamp | Date | The timestamp of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.user.id | String | The user ID in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.user.local_username | String | The local username in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.update_event.user.local_id | String | The local ID in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.version_id | String | The version ID of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.id | String | The ID of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.type | String | The type of cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.name | String | The name of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.source.cloud_connector.account_id | String | The account ID of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.id | String | The ID of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.display_name | String | The display name of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.datastore_id | String | The datastore ID associated with the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.dataset_sensitivity | String | The sensitivity classification of the dataset in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.dataset_ids | String | The list of dataset IDs associated with the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.object_type | String | The object type \(e.g. file, removable_storage\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.state | String | The state of the object \(e.g. active\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.content.tags | String | The content classification tags in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.content.attributes | String | The content attributes in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.content.upload_filename | String | The upload filename of the content in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.content.inspected | Boolean | Whether the content was inspected in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.data.labels | String | The data classification labels in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.data.label_ids | String | The data classification label IDs in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.name | String | The name of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.description | String | The description of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.package_name | String | The package name of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.binary_path | String | The binary path of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.command_line | String | The command line of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.app.main_window_title | String | The main window title of the associated application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.name | String | The file name in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.extension | String | The file extension in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.size | Number | The file size \(bytes\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.md5_hash | String | The MD5 hash of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.sha256_hash | String | The SHA-256 hash of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.created_at | Date | The creation timestamp of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.modified_at | Date | The last modification timestamp of the file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.owner.name | String | The name of the file owner in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.file.owner.id | String | The ID of the file owner in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.local_file.id | String | The local file ID in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.local_file.path | String | The local file system path in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.network_share.hostname | String | The hostname of the network share in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.network_share.path | String | The path of the network share in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.id | String | The ID of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.from | String | The sender of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.to | String | The recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.cc | String | The CC recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.bcc | String | The BCC recipients of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email.subject | String | The subject of the email in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.email_attachment.id | String | The ID of the email attachment in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.url | String | The URL of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.domain | String | The domain of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.category | String | The category of the web endpoint \(e.g. cloud_storage\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.download_url | String | The download URL of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.title | String | The page title of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.web.user_agent | String | The user-agent string of the web endpoint in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.provider | String | The cloud provider \(e.g. google\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.name | String | The name of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.user_name | String | The username in the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.user_email | String | The user email in the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.instance_id | String | The instance ID of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_app.instance_name | String | The instance name of the cloud application in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_file.id | String | The ID of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_file.content_uri | String | The content URI of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_file.path | String | The path of the cloud file in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_share_recipient.scope | String | The sharing scope in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_share_recipient.role | String | The role of the cloud share recipient in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.name | String | The name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.description | String | The description of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.physical_location | String | The physical location of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.server | String | The print server hostname in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.share_name | String | The share name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.port | String | The port of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.driver | String | The driver name of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.is_local | Boolean | Whether the printer is local in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.job_id | String | The print job ID in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.printer.connectivity | String | The connectivity type of the printer in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.id | String | The ID of the removable storage device in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.name | String | The name of the removable storage device in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.vendor_id | String | The USB vendor ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.removable_storage.product_id | String | The USB product ID of the removable storage in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.sender | String | The sender of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.recipient_users | String | The recipient users of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.recipient_groups | String | The recipient groups of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.domain | String | The domain of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.im_message.workspace | String | The workspace of the IM message in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.source_code_repo.organization | String | The organization of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.source_code_repo.name | String | The name of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.source_code_repo.branch | String | The branch of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.source_code_repo.id | String | The ID of the source code repository in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.labels | String | The labels applied to the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.label_ids | String | The label IDs applied to the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.matched_policies | String | The list of DLP policies matched by the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.issues | String | The list of DLP issues detected on the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.outline | String | The outline description of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.type | String | The endpoint type \(e.g. endpoint, removable_media\) in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.domain | String | The domain of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.discovered_at | Date | The timestamp when the object was first discovered in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.updated_at | Date | The timestamp when the object was last updated in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.id | String | The ID of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.action_kind | String | The action kind of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.timestamp | Date | The timestamp of the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.user.id | String | The user ID in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.user.local_username | String | The local username in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.update_event.user.local_id | String | The local ID in the update event in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.version_id | String | The version ID of the object in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.id | String | The ID of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.type | String | The type of cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.name | String | The name of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector in the end event. |
| Cyberhaven.Incident.event_details.end_event.destination.cloud_connector.account_id | String | The account ID of the cloud connector in the end event. |

#### Command example

```!cyberhaven-incident-update incident_id="inc_a1b2c3d4e5f6" status="Closed"```

#### Context Example

```json
{
    "Cyberhaven": {
        "Incidents": [
            {
                "id": "inc_a1b2c3d4e5f6",
                "user": {
                    "id": "usr_john_doe_001",
                    "local_username": "john.doe",
                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                    "custom_data": {
                        "department": "Engineering",
                        "manager_email": "jane.smith@company.com",
                        "employee_id": "EMP-10042",
                        "location": "US-NYC",
                        "role": "Senior Software Engineer"
                    }
                },
                "event_lineage_id": {
                    "start_event_id": "evt_start_001abc",
                    "end_event_id": "evt_end_002xyz"
                },
                "blocked": false,
                "event_time": "2026-01-15T10:28:45Z",
                "trigger_time": "2026-01-15T10:29:02Z",
                "dataset": {
                    "id": "ds_hr_confidential",
                    "name": "HR Confidential Records",
                    "sensitivity": "high",
                    "custom_data": {
                        "classification_level": "confidential",
                        "data_owner": "hr@company.com"
                    }
                },
                "user_risk_groups": [
                    {
                        "id": "rg_high_risk_users",
                        "name": "High Risk Users",
                        "risk_multiplier": 1.5,
                        "custom_data": {
                            "criteria": "multiple_policy_violations"
                        }
                    }
                ],
                "policy": {
                    "id": "pol_dlp_hr_001",
                    "name": "HR Data Exfiltration Prevention",
                    "severity": "high",
                    "custom_data": {
                        "policy_owner": "security@company.com",
                        "enforcement_mode": "block",
                        "review_cycle": "quarterly",
                        "compliance_framework": "SOC2"
                    }
                },
                "risk_score": 8.5,
                "screenshot_guid": "scrn_7f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
                "warning_status": "warning_shown",
                "user_reactions": [
                    "reaction_acknowledged"
                ],
                "user_reaction_message": "I was transferring files for an approved project backup.",
                "reaction_time": "2026-01-15T10:31:15Z",
                "assigned_to": "analyst@company.com",
                "status": "closed",
                "resolution_time": "2026-01-15T14:45:00Z",
                "close_reason": "policy_violation",
                "close_note": "User violated data exfiltration policy. Escalated to HR.",
                "custom_data": {
                    "ticket_id": "JIRA-4521"
                },
                "created_by": "created_by_system",
                "ai_summary": "User john.doe attempted to copy confidential HR records to a removable USB drive. The action was detected by endpoint DLP and flagged as a high-severity policy violation.",
                "ai_severity": "high",
                "last_modified": "2026-01-15T11:00:00Z",
                "event_details": {
                    "start_event": {
                        "id": "evt_start_001abc",
                        "timestamp": "2026-01-15T10:28:45Z",
                        "action": {
                            "kind": "copy",
                            "blocked": false,
                            "data_size": 2048576,
                            "content": {
                                "tags": [
                                    "pii",
                                    "confidential"
                                ],
                                "attributes": {
                                    "word_count": 1500
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "encoding": "UTF-8"
                                },
                                "inspected": true
                            },
                            "sensor_kind": "endpoint",
                            "hostname": "WORKSTATION-NYC-042",
                            "machine_serial_number": "C02XK1JFHV2R",
                            "custom_data": {
                                "os_version": "Windows 11 22H2"
                            },
                            "ip_address": "192.168.1.100",
                            "device_type": "managed",
                            "temporary_blocked": false,
                            "fail_close_statuses": [
                                {
                                    "temporary_blocked": false,
                                    "dlp_api_status": "SUCCESS",
                                    "dlp_precondition": "DLP_PRECONDITION_MET",
                                    "action_status": "ACTION_STATUS_COMPLETED"
                                }
                            ],
                            "process_id": 4821,
                            "parent_process_id": 1024
                        },
                        "user": {
                            "id": "usr_john_doe_001",
                            "local_username": "john.doe",
                            "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                            "custom_data": {
                                "ad_group": "Domain Users",
                                "upn": "john.doe@company.com",
                                "last_login": "2026-01-15T08:05:00Z"
                            }
                        },
                        "source": {
                            "id": "src_local_001abc",
                            "display_name": "employee_salaries_2026.xlsx",
                            "datastore_id": "dstore_endpoint_01",
                            "dataset_sensitivity": "sensitivity_high",
                            "dataset_ids": [
                                "ds_hr_confidential"
                            ],
                            "object_type": "file",
                            "state": "active",
                            "content": {
                                "tags": [
                                    "pii",
                                    "confidential"
                                ],
                                "attributes": {
                                    "record_count": 250
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "classification": "confidential",
                                    "last_scan": "2026-01-10T09:00:00Z",
                                    "scan_result": "contains_pii",
                                    "owner_department": "HR"
                                },
                                "inspected": true
                            },
                            "data": {
                                "labels": [
                                    "PII",
                                    "Confidential",
                                    "HR Data"
                                ],
                                "label_ids": [
                                    "lbl_pii",
                                    "lbl_confidential"
                                ]
                            },
                            "app": {
                                "name": "Microsoft Excel",
                                "description": "Microsoft Office Spreadsheet Application",
                                "package_name": "com.microsoft.excel",
                                "binary_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                                "command_line": "\"EXCEL.EXE\" /e",
                                "main_window_title": "employee_salaries_2026.xlsx - Excel",
                                "custom_data": {
                                    "version": "16.0.17126.20132",
                                    "publisher": "Microsoft Corporation",
                                    "signed": "true",
                                    "install_date": "2023-06-01",
                                    "auto_update": "enabled"
                                }
                            },
                            "file": {
                                "name": "employee_salaries_2026.xlsx",
                                "extension": "xlsx",
                                "size": 2048576,
                                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "custom_data": {
                                    "creator": "john.doe",
                                    "last_modified_by": "jane.smith"
                                },
                                "created_at": "2026-01-10T09:00:00Z",
                                "modified_at": "2026-01-15T08:30:00Z",
                                "owner": {
                                    "name": "john.doe",
                                    "id": "usr_john_doe_001"
                                }
                            },
                            "local_file": {
                                "id": "lf_001abc",
                                "path": "C:\\Users\\john.doe\\Documents\\HR\\employee_salaries_2026.xlsx"
                            },
                            "network_share": {
                                "hostname": "FILESERVER-01",
                                "path": "\\\\FILESERVER-01\\HR\\Compensation",
                                "custom_data": {
                                    "share_type": "SMB"
                                }
                            },
                            "email": {
                                "id": "email_src_001",
                                "from": "john.doe@company.com",
                                "to": [
                                    "personal@gmail.com"
                                ],
                                "cc": [
                                    "backup@gmail.com"
                                ],
                                "bcc": [
                                    "archive@gmail.com"
                                ],
                                "subject": "Salary Data Backup",
                                "custom_data": {
                                    "message_id": "<20260115102845.001@company.com>",
                                    "x_mailer": "Microsoft Outlook 16.0"
                                }
                            },
                            "email_attachment": {
                                "id": "attach_src_001",
                                "custom_data": {
                                    "attachment_index": "0",
                                    "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                }
                            },
                            "web": {
                                "url": "https://drive.google.com/upload",
                                "domain": "drive.google.com",
                                "category": "cloud_storage",
                                "download_url": "https://drive.google.com/file/d/1abc123/view",
                                "title": "Google Drive - Upload",
                                "custom_data": {
                                    "referrer": "https://drive.google.com/",
                                    "request_method": "POST"
                                },
                                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                            },
                            "cloud_app": {
                                "provider": "google",
                                "name": "google_drive",
                                "user_name": "john.doe",
                                "user_email": "john.doe@personal.com",
                                "custom_data": {
                                    "tenant_id": "tenant_google_001",
                                    "app_version": "2026.1"
                                },
                                "instance_id": "gdrive_inst_001",
                                "instance_name": "Personal Google Drive"
                            },
                            "cloud_file": {
                                "id": "cf_src_001",
                                "content_uri": "https://drive.google.com/file/d/1abc123/content",
                                "path": "/My Drive/HR Data/employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "revision_id": "rev_001"
                                }
                            },
                            "cloud_share_recipient": {
                                "scope": "share_external",
                                "user_ids": [
                                    "external_user_001"
                                ],
                                "role": "role_viewer",
                                "custom_data": {
                                    "expiry_date": "2026-12-31",
                                    "notify_on_access": "true"
                                }
                            },
                            "printer": {
                                "name": "HP LaserJet Pro M404n",
                                "description": "Office Laser Printer - Floor 3",
                                "physical_location": "3rd Floor Copy Room",
                                "server": "PRINTSERVER-01",
                                "share_name": "HP-LaserJet-3F",
                                "port": "IP_192.168.1.200",
                                "driver": "HP LaserJet Pro M404n PCL 6",
                                "is_local": false,
                                "job_id": "print_job_4521",
                                "custom_data": {
                                    "pages_printed": "12",
                                    "duplex": "false"
                                },
                                "connectivity": "network"
                            },
                            "removable_storage": {
                                "id": "usb_src_001",
                                "name": "SanDisk Ultra 64GB",
                                "usb_id": "usb_0781_5581",
                                "vendor_id": "0781",
                                "product_id": "5581",
                                "custom_data": {
                                    "serial_number": "4C530001041120115283",
                                    "file_system": "NTFS",
                                    "capacity_gb": "64"
                                }
                            },
                            "im_message": {
                                "sender": "john.doe@company.com",
                                "recipient_users": [
                                    "personal.contact@gmail.com"
                                ],
                                "recipient_groups": [
                                    "external-group-001"
                                ],
                                "domain": "teams.microsoft.com",
                                "workspace": "Personal Chat",
                                "custom_data": {
                                    "message_id": "msg_001abc"
                                }
                            },
                            "source_code_repo": {
                                "organization": "company-org",
                                "name": "hr-data-scripts",
                                "custom_data": {
                                    "visibility": "private",
                                    "default_branch": "main",
                                    "last_commit": "a1b2c3d4e5f6",
                                    "language": "Python"
                                },
                                "branch": "main",
                                "id": "repo_001"
                            },
                            "labels": [
                                "PII",
                                "Confidential"
                            ],
                            "label_ids": [
                                "lbl_pii",
                                "lbl_confidential"
                            ],
                            "matched_policies": [
                                {
                                    "policy_type": "dlp",
                                    "id": "pol_dlp_hr_001",
                                    "version": 3,
                                    "definition_rule_ids": [
                                        "rule_pii_detection",
                                        "rule_confidential_data"
                                    ],
                                    "action_rule_id": "action_rule_block",
                                    "matched_at": "2026-01-15T10:28:45Z"
                                }
                            ],
                            "issues": [
                                {
                                    "id": "issue_001abc",
                                    "policy_type": "dlp",
                                    "matched_policy_id": "pol_dlp_hr_001",
                                    "policy_action_rule_id": "action_rule_block",
                                    "severity": "issue_severity_high",
                                    "detected_at": "2026-01-15T10:28:45Z"
                                }
                            ],
                            "custom_data": {
                                "data_classification": "confidential",
                                "retention_policy": "7_years",
                                "gdpr_relevant": "true",
                                "ccpa_relevant": "true"
                            },
                            "outline": "Spreadsheet containing employee salary and compensation data for 250 employees in the Engineering department.",
                            "type": "removable_media",
                            "domain": "company.com",
                            "discovered_at": "2026-01-10T09:00:00Z",
                            "updated_at": "2026-01-15T10:28:45Z",
                            "update_event": {
                                "id": "upd_evt_001",
                                "action_kind": "copy",
                                "timestamp": "2026-01-15T10:28:45Z",
                                "user": {
                                    "id": "usr_john_doe_001",
                                    "local_username": "john.doe",
                                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                                    "custom_data": {
                                        "session_id": "sess_20260115_001"
                                    }
                                }
                            },
                            "version_id": "ver_001abc",
                            "cloud_connector": {
                                "id": "cc_box_001",
                                "type": "box",
                                "name": "Company Box Integration",
                                "onboarding_account": "admin@company.com",
                                "account_id": "box_acct_001"
                            }
                        },
                        "destination": {
                            "id": "dst_usb_001abc",
                            "display_name": "SanDisk Ultra 64GB (E:)",
                            "datastore_id": "dstore_usb_01",
                            "dataset_sensitivity": "sensitivity_unspecified",
                            "dataset_ids": [
                                "ds_removable_default"
                            ],
                            "object_type": "removable_storage",
                            "state": "active",
                            "content": {
                                "tags": [
                                    "external",
                                    "removable"
                                ],
                                "attributes": {
                                    "file_count": 1,
                                    "total_size": 2048576
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "destination_path": "E:\\Backup\\HR",
                                    "overwrite": "false"
                                },
                                "inspected": true
                            },
                            "data": {
                                "labels": [
                                    "External Storage"
                                ],
                                "label_ids": [
                                    "lbl_external_storage"
                                ]
                            },
                            "app": {
                                "name": "Windows Explorer",
                                "description": "Windows File Explorer",
                                "package_name": "com.microsoft.explorer",
                                "binary_path": "C:\\Windows\\explorer.exe",
                                "command_line": "explorer.exe /select,\"E:\\Backup\\HR\\employee_salaries_2026.xlsx\"",
                                "main_window_title": "E:\\Backup\\HR",
                                "custom_data": {
                                    "version": "10.0.22621.1"
                                }
                            },
                            "file": {
                                "name": "employee_salaries_2026.xlsx",
                                "extension": "xlsx",
                                "size": 2048576,
                                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "custom_data": {
                                    "destination_created": "true",
                                    "is_copy": "true",
                                    "original_path": "C:\\Users\\john.doe\\Documents\\HR\\employee_salaries_2026.xlsx"
                                },
                                "created_at": "2026-01-15T10:28:50Z",
                                "modified_at": "2026-01-15T10:28:50Z",
                                "owner": {
                                    "name": "john.doe",
                                    "id": "usr_john_doe_001"
                                }
                            },
                            "local_file": {
                                "id": "lf_dst_001",
                                "path": "E:\\Backup\\HR\\employee_salaries_2026.xlsx"
                            },
                            "network_share": {
                                "hostname": "FILESERVER-01",
                                "path": "\\\\FILESERVER-01\\Backup\\HR",
                                "custom_data": {
                                    "share_type": "SMB"
                                }
                            },
                            "email": {
                                "id": "email_dst_001",
                                "from": "john.doe@company.com",
                                "to": [
                                    "personal@gmail.com"
                                ],
                                "cc": [
                                    "backup@gmail.com"
                                ],
                                "bcc": [
                                    "archive@gmail.com"
                                ],
                                "subject": "Salary Data Backup",
                                "custom_data": {
                                    "message_id": "<20260115102845.001@company.com>"
                                }
                            },
                            "email_attachment": {
                                "id": "attach_dst_001",
                                "custom_data": {
                                    "attachment_index": "0",
                                    "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "file_size": "2048576",
                                    "sanitized": "false"
                                }
                            },
                            "web": {
                                "url": "https://drive.google.com/upload/resumable",
                                "domain": "drive.google.com",
                                "category": "cloud_storage",
                                "download_url": "https://drive.google.com/file/d/1abc123/view",
                                "title": "Google Drive - Upload Complete",
                                "custom_data": {
                                    "upload_session_id": "upload_sess_001"
                                },
                                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                            },
                            "cloud_app": {
                                "provider": "google",
                                "name": "google_drive",
                                "user_name": "john.doe",
                                "user_email": "john.doe@personal.com",
                                "custom_data": {
                                    "upload_complete": "true"
                                },
                                "instance_id": "gdrive_inst_001",
                                "instance_name": "Personal Google Drive"
                            },
                            "cloud_file": {
                                "id": "cf_dst_001",
                                "content_uri": "https://drive.google.com/file/d/1abc123/content",
                                "path": "/My Drive/HR Backup/employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "upload_timestamp": "2026-01-15T10:29:00Z",
                                    "file_id": "1abc123xyz"
                                }
                            },
                            "cloud_share_recipient": {
                                "scope": "share_external",
                                "user_ids": [
                                    "external_user_001",
                                    "external_user_002"
                                ],
                                "role": "role_viewer",
                                "custom_data": {
                                    "expiry_date": "2026-12-31",
                                    "notify_on_access": "true",
                                    "link_type": "restricted"
                                }
                            },
                            "printer": {
                                "name": "HP LaserJet Pro M404n",
                                "description": "Office Laser Printer - Floor 3",
                                "physical_location": "3rd Floor Copy Room",
                                "server": "PRINTSERVER-01",
                                "share_name": "HP-LaserJet-3F",
                                "port": "IP_192.168.1.200",
                                "driver": "HP LaserJet Pro M404n PCL 6",
                                "is_local": false,
                                "job_id": "print_job_4521",
                                "custom_data": {
                                    "pages_printed": "12"
                                },
                                "connectivity": "network"
                            },
                            "removable_storage": {
                                "id": "usb_dst_001",
                                "name": "SanDisk Ultra 64GB",
                                "usb_id": "usb_0781_5581",
                                "vendor_id": "0781",
                                "product_id": "5581",
                                "custom_data": {
                                    "serial_number": "4C530001041120115283",
                                    "drive_letter": "E",
                                    "free_space_gb": "45"
                                }
                            },
                            "im_message": {
                                "sender": "john.doe@company.com",
                                "recipient_users": [
                                    "personal.contact@gmail.com"
                                ],
                                "recipient_groups": [
                                    "external-group-001"
                                ],
                                "domain": "teams.microsoft.com",
                                "workspace": "Personal Chat",
                                "custom_data": {
                                    "message_id": "msg_dst_001",
                                    "channel": "direct",
                                    "platform": "teams",
                                    "thread_id": "thread_001",
                                    "is_external": "true"
                                }
                            },
                            "source_code_repo": {
                                "organization": "personal-org",
                                "name": "personal-backup-repo",
                                "custom_data": {
                                    "visibility": "private"
                                },
                                "branch": "main",
                                "id": "repo_dst_001"
                            },
                            "labels": [
                                "External Storage",
                                "Removable Media"
                            ],
                            "label_ids": [
                                "lbl_external_storage",
                                "lbl_removable_media"
                            ],
                            "matched_policies": [
                                {
                                    "policy_type": "dlp",
                                    "id": "pol_dlp_removable_001",
                                    "version": 2,
                                    "definition_rule_ids": [
                                        "rule_removable_media_write"
                                    ],
                                    "action_rule_id": "action_rule_alert",
                                    "matched_at": "2026-01-15T10:28:50Z"
                                }
                            ],
                            "issues": [
                                {
                                    "id": "issue_dst_001",
                                    "policy_type": "dlp",
                                    "matched_policy_id": "pol_dlp_removable_001",
                                    "policy_action_rule_id": "action_rule_alert",
                                    "severity": "issue_severity_high",
                                    "detected_at": "2026-01-15T10:28:50Z"
                                }
                            ],
                            "custom_data": {
                                "endpoint_risk": "high",
                                "device_approved": "false"
                            },
                            "outline": "USB removable storage device used as destination for confidential HR file transfer.",
                            "type": "share",
                            "domain": "company.com",
                            "discovered_at": "2026-01-15T10:28:45Z",
                            "updated_at": "2026-01-15T10:28:50Z",
                            "update_event": {
                                "id": "upd_evt_dst_001",
                                "action_kind": "write",
                                "timestamp": "2026-01-15T10:28:50Z",
                                "user": {
                                    "id": "usr_john_doe_001",
                                    "local_username": "john.doe",
                                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                                    "custom_data": {
                                        "session_id": "sess_20260115_001"
                                    }
                                }
                            },
                            "version_id": "ver_dst_001",
                            "cloud_connector": {
                                "id": "cc_gcs_001",
                                "type": "gcs",
                                "name": "Company GCS Integration",
                                "onboarding_account": "gcs-service@company.iam.gserviceaccount.com",
                                "account_id": "gcs_acct_001"
                            }
                        }
                    },
                    "end_event": {
                        "id": "evt_end_002xyz",
                        "timestamp": "2026-01-15T10:29:00Z",
                        "action": {
                            "kind": "upload",
                            "blocked": false,
                            "data_size": 2048576,
                            "content": {
                                "tags": [
                                    "pii",
                                    "confidential"
                                ],
                                "attributes": {
                                    "word_count": 1500,
                                    "page_count": 3
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "encoding": "UTF-8",
                                    "compressed": "false",
                                    "checksum_verified": "true"
                                },
                                "inspected": true
                            },
                            "sensor_kind": "endpoint",
                            "hostname": "WORKSTATION-NYC-042",
                            "machine_serial_number": "C02XK1JFHV2R",
                            "custom_data": {
                                "os_version": "Windows 11 22H2",
                                "network_zone": "internal"
                            },
                            "ip_address": "192.168.1.100",
                            "device_type": "managed",
                            "temporary_blocked": false,
                            "fail_close_statuses": [
                                {
                                    "temporary_blocked": false,
                                    "dlp_api_status": "SUCCESS",
                                    "dlp_precondition": "DLP_PRECONDITION_MET",
                                    "action_status": "ACTION_STATUS_COMPLETED"
                                }
                            ],
                            "process_id": 4821,
                            "parent_process_id": 1024
                        },
                        "user": {
                            "id": "usr_john_doe_001",
                            "local_username": "john.doe",
                            "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                            "custom_data": {
                                "session_id": "sess_20260115_001"
                            }
                        },
                        "source": {
                            "id": "src_end_001abc",
                            "display_name": "E:\\Backup\\HR\\employee_salaries_2026.xlsx",
                            "datastore_id": "dstore_usb_01",
                            "dataset_sensitivity": "sensitivity_unspecified",
                            "dataset_ids": [
                                "ds_removable_default"
                            ],
                            "object_type": "file",
                            "state": "active",
                            "content": {
                                "tags": [
                                    "pii",
                                    "confidential"
                                ],
                                "attributes": {
                                    "record_count": 250
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "path": "E:\\Backup\\HR\\employee_salaries_2026.xlsx"
                                },
                                "inspected": true
                            },
                            "data": {
                                "labels": [
                                    "PII",
                                    "Confidential"
                                ],
                                "label_ids": [
                                    "lbl_pii",
                                    "lbl_confidential"
                                ]
                            },
                            "app": {
                                "name": "Windows Explorer",
                                "description": "Windows File Explorer",
                                "package_name": "com.microsoft.explorer",
                                "binary_path": "C:\\Windows\\explorer.exe",
                                "command_line": "explorer.exe",
                                "main_window_title": "E:\\Backup\\HR",
                                "custom_data": {
                                    "version": "10.0.22621.1"
                                }
                            },
                            "file": {
                                "name": "employee_salaries_2026.xlsx",
                                "extension": "xlsx",
                                "size": 2048576,
                                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "custom_data": {
                                    "drive_letter": "E"
                                },
                                "created_at": "2026-01-15T10:28:50Z",
                                "modified_at": "2026-01-15T10:28:50Z",
                                "owner": {
                                    "name": "john.doe",
                                    "id": "usr_john_doe_001"
                                }
                            },
                            "local_file": {
                                "id": "lf_end_src_001",
                                "path": "E:\\Backup\\HR\\employee_salaries_2026.xlsx"
                            },
                            "network_share": {
                                "hostname": "FILESERVER-01",
                                "path": "\\\\FILESERVER-01\\HR\\Compensation",
                                "custom_data": {
                                    "share_type": "SMB",
                                    "mount_point": "Z:"
                                }
                            },
                            "email": {
                                "id": "email_end_src_001",
                                "from": "john.doe@company.com",
                                "to": [
                                    "personal@gmail.com"
                                ],
                                "cc": [
                                    "backup@gmail.com"
                                ],
                                "bcc": [
                                    "archive@gmail.com"
                                ],
                                "subject": "Salary Data Backup",
                                "custom_data": {
                                    "message_id": "<20260115102900.002@company.com>"
                                }
                            },
                            "email_attachment": {
                                "id": "attach_end_src_001",
                                "custom_data": {
                                    "attachment_index": "0"
                                }
                            },
                            "web": {
                                "url": "https://drive.google.com/upload",
                                "domain": "drive.google.com",
                                "category": "cloud_storage",
                                "download_url": "https://drive.google.com/file/d/1abc123/view",
                                "title": "Google Drive",
                                "custom_data": {
                                    "referrer": "https://drive.google.com/",
                                    "request_method": "POST",
                                    "response_code": "200"
                                },
                                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                            },
                            "cloud_app": {
                                "provider": "google",
                                "name": "google_drive",
                                "user_name": "john.doe",
                                "user_email": "john.doe@personal.com",
                                "custom_data": {
                                    "tenant_id": "tenant_google_001",
                                    "app_version": "2026.1",
                                    "auth_method": "oauth2"
                                },
                                "instance_id": "gdrive_inst_001",
                                "instance_name": "Personal Google Drive"
                            },
                            "cloud_file": {
                                "id": "cf_end_src_001",
                                "content_uri": "https://drive.google.com/file/d/1abc123/content",
                                "path": "/My Drive/HR Backup/employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "file_id": "1abc123xyz",
                                    "revision": "1"
                                }
                            },
                            "cloud_share_recipient": {
                                "scope": "share_external",
                                "user_ids": [
                                    "external_user_001"
                                ],
                                "role": "role_viewer",
                                "custom_data": {
                                    "expiry_date": "2026-12-31"
                                }
                            },
                            "printer": {
                                "name": "HP LaserJet Pro M404n",
                                "description": "Office Laser Printer - Floor 3",
                                "physical_location": "3rd Floor Copy Room",
                                "server": "PRINTSERVER-01",
                                "share_name": "HP-LaserJet-3F",
                                "port": "IP_192.168.1.200",
                                "driver": "HP LaserJet Pro M404n PCL 6",
                                "is_local": false,
                                "job_id": "print_job_4522",
                                "custom_data": {
                                    "pages_printed": "12"
                                },
                                "connectivity": "network"
                            },
                            "removable_storage": {
                                "id": "usb_end_src_001",
                                "name": "SanDisk Ultra 64GB",
                                "usb_id": "usb_0781_5581",
                                "vendor_id": "0781",
                                "product_id": "5581",
                                "custom_data": {
                                    "serial_number": "4C530001041120115283",
                                    "file_system": "NTFS",
                                    "drive_letter": "E"
                                }
                            },
                            "im_message": {
                                "sender": "john.doe@company.com",
                                "recipient_users": [
                                    "personal.contact@gmail.com"
                                ],
                                "recipient_groups": [
                                    "external-group-001"
                                ],
                                "domain": "teams.microsoft.com",
                                "workspace": "Personal Chat",
                                "custom_data": {
                                    "message_id": "msg_end_001",
                                    "platform": "teams",
                                    "thread_id": "thread_001",
                                    "channel_type": "direct_message"
                                }
                            },
                            "source_code_repo": {
                                "organization": "company-org",
                                "name": "hr-data-scripts",
                                "custom_data": {
                                    "visibility": "private"
                                },
                                "branch": "main",
                                "id": "repo_end_src_001"
                            },
                            "labels": [
                                "External Storage",
                                "PII"
                            ],
                            "label_ids": [
                                "lbl_external_storage",
                                "lbl_pii"
                            ],
                            "matched_policies": [
                                {
                                    "policy_type": "dlp",
                                    "id": "pol_dlp_hr_001",
                                    "version": 3,
                                    "definition_rule_ids": [
                                        "rule_pii_detection"
                                    ],
                                    "action_rule_id": "action_rule_block",
                                    "matched_at": "2026-01-15T10:29:00Z"
                                }
                            ],
                            "issues": [
                                {
                                    "id": "issue_end_src_001",
                                    "policy_type": "dlp",
                                    "matched_policy_id": "pol_dlp_hr_001",
                                    "policy_action_rule_id": "action_rule_block",
                                    "severity": "issue_severity_high",
                                    "detected_at": "2026-01-15T10:29:00Z"
                                }
                            ],
                            "custom_data": {
                                "data_classification": "confidential",
                                "risk_level": "high",
                                "source_type": "removable_media"
                            },
                            "outline": "File read from USB removable storage during end event of the data transfer sequence.",
                            "type": "endpoint",
                            "domain": "company.com",
                            "discovered_at": "2026-01-15T10:28:50Z",
                            "updated_at": "2026-01-15T10:29:00Z",
                            "update_event": {
                                "id": "upd_evt_end_src_001",
                                "action_kind": "read",
                                "timestamp": "2026-01-15T10:29:00Z",
                                "user": {
                                    "id": "usr_john_doe_001",
                                    "local_username": "john.doe",
                                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                                    "custom_data": {
                                        "session_id": "sess_20260115_001"
                                    }
                                }
                            },
                            "version_id": "ver_end_src_001",
                            "cloud_connector": {
                                "id": "cc_salesforce_001",
                                "type": "salesforce",
                                "name": "Company Salesforce Integration",
                                "onboarding_account": "admin@company.com",
                                "account_id": "sf_acct_001"
                            }
                        },
                        "destination": {
                            "id": "dst_end_001abc",
                            "display_name": "Google Drive - Personal",
                            "datastore_id": "dstore_gdrive_01",
                            "dataset_sensitivity": "sensitivity_unspecified",
                            "dataset_ids": [
                                "ds_external_cloud"
                            ],
                            "object_type": "cloud_file",
                            "state": "active",
                            "content": {
                                "tags": [
                                    "external",
                                    "cloud"
                                ],
                                "attributes": {
                                    "file_count": 1,
                                    "total_size": 2048576,
                                    "upload_chunks": 2,
                                    "retry_count": 0,
                                    "transfer_duration_ms": 1250
                                },
                                "upload_filename": "employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "upload_method": "resumable",
                                    "destination_folder": "/My Drive/HR Backup",
                                    "overwrite_existing": "false"
                                },
                                "inspected": true
                            },
                            "data": {
                                "labels": [
                                    "External",
                                    "Cloud Storage"
                                ],
                                "label_ids": [
                                    "lbl_external",
                                    "lbl_cloud_storage"
                                ]
                            },
                            "app": {
                                "name": "Google Chrome",
                                "description": "Google Chrome Web Browser",
                                "package_name": "com.google.chrome",
                                "binary_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                "command_line": "chrome.exe --profile-directory=Default",
                                "main_window_title": "Google Drive - Google Chrome",
                                "custom_data": {
                                    "version": "120.0.6099.130",
                                    "profile": "Default"
                                }
                            },
                            "file": {
                                "name": "employee_salaries_2026.xlsx",
                                "extension": "xlsx",
                                "size": 2048576,
                                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "custom_data": {
                                    "cloud_file_id": "1abc123xyz",
                                    "upload_session": "upload_sess_001"
                                },
                                "created_at": "2026-01-15T10:29:05Z",
                                "modified_at": "2026-01-15T10:29:05Z",
                                "owner": {
                                    "name": "john.doe",
                                    "id": "usr_john_doe_001"
                                }
                            },
                            "local_file": {
                                "id": "lf_end_dst_001",
                                "path": "C:\\Users\\john.doe\\Downloads\\employee_salaries_2026.xlsx"
                            },
                            "network_share": {
                                "hostname": "EXTERNAL-SHARE-01",
                                "path": "\\\\EXTERNAL-SHARE-01\\Public",
                                "custom_data": {
                                    "share_type": "SMB",
                                    "external_network": "true"
                                }
                            },
                            "email": {
                                "id": "email_end_dst_001",
                                "from": "john.doe@company.com",
                                "to": [
                                    "personal@gmail.com"
                                ],
                                "cc": [
                                    "backup@gmail.com"
                                ],
                                "bcc": [
                                    "archive@gmail.com"
                                ],
                                "subject": "Salary Data Backup",
                                "custom_data": {
                                    "message_id": "<20260115102900.002@company.com>",
                                    "smtp_server": "smtp.gmail.com"
                                }
                            },
                            "email_attachment": {
                                "id": "attach_end_dst_001",
                                "custom_data": {
                                    "attachment_index": "0",
                                    "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    "file_size": "2048576",
                                    "sanitized": "false"
                                }
                            },
                            "web": {
                                "url": "https://drive.google.com/file/d/1abc123xyz/view",
                                "domain": "drive.google.com",
                                "category": "cloud_storage",
                                "download_url": "https://drive.google.com/uc?id=1abc123xyz&export=download",
                                "title": "employee_salaries_2026.xlsx - Google Drive",
                                "custom_data": {
                                    "file_id": "1abc123xyz",
                                    "sharing_status": "private"
                                },
                                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                            },
                            "cloud_app": {
                                "provider": "google",
                                "name": "google_drive",
                                "user_name": "john.doe",
                                "user_email": "john.doe@personal.com",
                                "custom_data": {
                                    "account_type": "personal"
                                },
                                "instance_id": "gdrive_inst_001",
                                "instance_name": "Personal Google Drive"
                            },
                            "cloud_file": {
                                "id": "cf_end_dst_001",
                                "content_uri": "https://drive.google.com/file/d/1abc123xyz/content",
                                "path": "/My Drive/HR Backup/employee_salaries_2026.xlsx",
                                "custom_data": {
                                    "file_id": "1abc123xyz",
                                    "revision_id": "rev_001",
                                    "upload_complete": "true"
                                }
                            },
                            "cloud_share_recipient": {
                                "scope": "share_external",
                                "user_ids": [
                                    "external_user_001",
                                    "external_user_002",
                                    "external_user_003"
                                ],
                                "role": "role_editor",
                                "custom_data": {
                                    "expiry_date": "2026-12-31",
                                    "link_type": "restricted",
                                    "notify_on_download": "true"
                                }
                            },
                            "printer": {
                                "name": "HP LaserJet Pro M404n",
                                "description": "Office Laser Printer - Floor 3",
                                "physical_location": "3rd Floor Copy Room",
                                "server": "PRINTSERVER-01",
                                "share_name": "HP-LaserJet-3F",
                                "port": "IP_192.168.1.200",
                                "driver": "HP LaserJet Pro M404n PCL 6",
                                "is_local": false,
                                "job_id": "print_job_4523",
                                "custom_data": {
                                    "pages_printed": "12",
                                    "color": "false"
                                },
                                "connectivity": "network"
                            },
                            "removable_storage": {
                                "id": "usb_end_dst_001",
                                "name": "SanDisk Ultra 64GB",
                                "usb_id": "usb_0781_5581",
                                "vendor_id": "0781",
                                "product_id": "5581",
                                "custom_data": {
                                    "serial_number": "4C530001041120115283"
                                }
                            },
                            "im_message": {
                                "sender": "john.doe@company.com",
                                "recipient_users": [
                                    "personal.contact@gmail.com"
                                ],
                                "recipient_groups": [
                                    "external-group-001"
                                ],
                                "domain": "teams.microsoft.com",
                                "workspace": "Personal Chat",
                                "custom_data": {
                                    "message_id": "msg_end_dst_001"
                                }
                            },
                            "source_code_repo": {
                                "organization": "personal-org",
                                "name": "personal-backup-repo",
                                "custom_data": {
                                    "visibility": "private",
                                    "language": "Python",
                                    "size_kb": "1024"
                                },
                                "branch": "main",
                                "id": "repo_end_dst_001"
                            },
                            "labels": [
                                "External",
                                "Cloud Storage",
                                "Personal Account"
                            ],
                            "label_ids": [
                                "lbl_external",
                                "lbl_cloud_storage"
                            ],
                            "matched_policies": [
                                {
                                    "policy_type": "dlp",
                                    "id": "pol_dlp_cloud_upload_001",
                                    "version": 1,
                                    "definition_rule_ids": [
                                        "rule_cloud_upload_block"
                                    ],
                                    "action_rule_id": "action_rule_block",
                                    "matched_at": "2026-01-15T10:29:00Z"
                                }
                            ],
                            "issues": [
                                {
                                    "id": "issue_end_dst_001",
                                    "policy_type": "dlp",
                                    "matched_policy_id": "pol_dlp_cloud_upload_001",
                                    "policy_action_rule_id": "action_rule_block",
                                    "severity": "issue_severity_high",
                                    "detected_at": "2026-01-15T10:29:00Z"
                                }
                            ],
                            "custom_data": {
                                "upload_destination": "personal_cloud",
                                "risk_level": "critical"
                            },
                            "outline": "Personal Google Drive account used as destination for unauthorized data upload containing HR confidential records.",
                            "type": "removable_media",
                            "domain": "drive.google.com",
                            "discovered_at": "2026-01-15T10:29:00Z",
                            "updated_at": "2026-01-15T10:29:05Z",
                            "update_event": {
                                "id": "upd_evt_end_dst_001",
                                "action_kind": "upload",
                                "timestamp": "2026-01-15T10:29:05Z",
                                "user": {
                                    "id": "usr_john_doe_001",
                                    "local_username": "john.doe",
                                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                                    "custom_data": {
                                        "session_id": "sess_20260115_001"
                                    }
                                }
                            },
                            "version_id": "ver_end_dst_001",
                            "cloud_connector": {
                                "id": "cc_teams_001",
                                "type": "teams",
                                "name": "Company Teams Integration",
                                "onboarding_account": "teams-admin@company.com",
                                "account_id": "teams_acct_001"
                            }
                        }
                    }
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Incident **inc_a1b2c3d4e5f6** updated successfully
>
>|ID|Policy|Severity|Status|Blocked|Event Time|Start Event ID|End Event ID|AI Summary|
>|---|---|---|---|---|---|---|---|---|
>| [inc_a1b2c3d4e5f6](https://your-tenant.cyberhaven.io/incidents?id=inc_a1b2c3d4e5f6) | HR Data Exfiltration Prevention | high | closed | false | 2026-01-15T10:28:45Z | evt_start_001abc | evt_end_002xyz | User john.doe attempted to copy confidential HR records to a removable USB drive. The action was detected by endpoint DLP and flagged as a high-severity policy violation. |

### cyberhaven-event-details-get

***
Retrieves full details for one or more Cyberhaven events by ID.

#### Base Command

`cyberhaven-event-details-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | A comma-separated list of event UUIDs to get the events. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberhaven.Event.id | String | The unique identifier of the event. |
| Cyberhaven.Event.timestamp | Date | The timestamp when the event occurred. |
| Cyberhaven.Event.action.kind | String | The kind of action performed \(e.g. copy, upload\). |
| Cyberhaven.Event.action.blocked | Boolean | Whether the action was blocked by policy. |
| Cyberhaven.Event.action.data_size | Number | The size of data involved in the action \(bytes\). |
| Cyberhaven.Event.action.content.tags | String | The content classification tags detected in the action. |
| Cyberhaven.Event.action.content.attributes | String | The content attributes of the action. |
| Cyberhaven.Event.action.content.upload_filename | String | The filename of the content being uploaded in the action. |
| Cyberhaven.Event.action.content.inspected | Boolean | Whether the content was inspected in the action. |
| Cyberhaven.Event.action.sensor_kind | String | The sensor type that detected the action \(e.g. endpoint\). |
| Cyberhaven.Event.action.hostname | String | The hostname of the machine where the action occurred. |
| Cyberhaven.Event.action.machine_serial_number | String | The serial number of the machine where the action occurred. |
| Cyberhaven.Event.action.ip_address | String | The IP address of the machine where the action occurred. |
| Cyberhaven.Event.action.device_type | String | The device management type \(e.g. managed\). |
| Cyberhaven.Event.action.temporary_blocked | Boolean | Whether the action was temporarily blocked. |
| Cyberhaven.Event.action.fail_close_statuses | String | The list of fail-close status objects for the action. |
| Cyberhaven.Event.action.process_id | Number | The process ID of the process that triggered the action. |
| Cyberhaven.Event.action.parent_process_id | Number | The parent process ID of the process that triggered the action. |
| Cyberhaven.Event.user.id | String | The identifier of the user who triggered the event. |
| Cyberhaven.Event.user.local_username | String | The local machine username of the user who triggered the event. |
| Cyberhaven.Event.user.local_id | String | The local identifier of the user who triggered the event. |
| Cyberhaven.Event.source.id | String | The ID of the object. |
| Cyberhaven.Event.source.display_name | String | The display name of the object. |
| Cyberhaven.Event.source.datastore_id | String | The datastore ID associated with the object. |
| Cyberhaven.Event.source.dataset_sensitivity | String | The sensitivity classification of the dataset. |
| Cyberhaven.Event.source.dataset_ids | String | The list of dataset IDs associated with the object. |
| Cyberhaven.Event.source.object_type | String | The object type \(e.g. file, removable_storage\). |
| Cyberhaven.Event.source.state | String | The state of the object \(e.g. active\). |
| Cyberhaven.Event.source.content.tags | String | The content classification tags. |
| Cyberhaven.Event.source.content.attributes | String | The content attributes. |
| Cyberhaven.Event.source.content.upload_filename | String | The upload filename of the content. |
| Cyberhaven.Event.source.content.inspected | Boolean | Whether the content was inspected. |
| Cyberhaven.Event.source.data.labels | String | The data classification labels. |
| Cyberhaven.Event.source.data.label_ids | String | The data classification label IDs. |
| Cyberhaven.Event.source.app.name | String | The name of the associated application. |
| Cyberhaven.Event.source.app.description | String | The description of the associated application. |
| Cyberhaven.Event.source.app.package_name | String | The package name of the associated application. |
| Cyberhaven.Event.source.app.binary_path | String | The binary path of the associated application. |
| Cyberhaven.Event.source.app.command_line | String | The command line of the associated application. |
| Cyberhaven.Event.source.app.main_window_title | String | The main window title of the associated application. |
| Cyberhaven.Event.source.file.name | String | The file name. |
| Cyberhaven.Event.source.file.extension | String | The file extension. |
| Cyberhaven.Event.source.file.size | Number | The file size \(bytes\). |
| Cyberhaven.Event.source.file.md5_hash | String | The MD5 hash of the file. |
| Cyberhaven.Event.source.file.sha256_hash | String | The SHA-256 hash of the file. |
| Cyberhaven.Event.source.file.created_at | Date | The creation timestamp of the file. |
| Cyberhaven.Event.source.file.modified_at | Date | The last modification timestamp of the file. |
| Cyberhaven.Event.source.file.owner.name | String | The name of the file owner. |
| Cyberhaven.Event.source.file.owner.id | String | The ID of the file owner. |
| Cyberhaven.Event.source.local_file.id | String | The local file ID. |
| Cyberhaven.Event.source.local_file.path | String | The local file system path. |
| Cyberhaven.Event.source.network_share.hostname | String | The hostname of the network share. |
| Cyberhaven.Event.source.network_share.path | String | The path of the network share. |
| Cyberhaven.Event.source.email.id | String | The ID of the email. |
| Cyberhaven.Event.source.email.from | String | The sender of the email. |
| Cyberhaven.Event.source.email.to | String | The recipients of the email. |
| Cyberhaven.Event.source.email.cc | String | The CC recipients of the email. |
| Cyberhaven.Event.source.email.bcc | String | The BCC recipients of the email. |
| Cyberhaven.Event.source.email.subject | String | The subject of the email. |
| Cyberhaven.Event.source.email_attachment.id | String | The ID of the email attachment. |
| Cyberhaven.Event.source.web.url | String | The URL of the web endpoint. |
| Cyberhaven.Event.source.web.domain | String | The domain of the web endpoint. |
| Cyberhaven.Event.source.web.category | String | The category of the web endpoint \(e.g. cloud_storage\). |
| Cyberhaven.Event.source.web.download_url | String | The download URL of the web endpoint. |
| Cyberhaven.Event.source.web.title | String | The page title of the web endpoint. |
| Cyberhaven.Event.source.web.user_agent | String | The user-agent string of the web endpoint. |
| Cyberhaven.Event.source.cloud_app.provider | String | The cloud provider \(e.g. google\). |
| Cyberhaven.Event.source.cloud_app.name | String | The name of the cloud application. |
| Cyberhaven.Event.source.cloud_app.user_name | String | The username in the cloud application. |
| Cyberhaven.Event.source.cloud_app.user_email | String | The user email in the cloud application. |
| Cyberhaven.Event.source.cloud_app.instance_id | String | The instance ID of the cloud application. |
| Cyberhaven.Event.source.cloud_app.instance_name | String | The instance name of the cloud application. |
| Cyberhaven.Event.source.cloud_file.id | String | The ID of the cloud file. |
| Cyberhaven.Event.source.cloud_file.content_uri | String | The content URI of the cloud file. |
| Cyberhaven.Event.source.cloud_file.path | String | The path of the cloud file. |
| Cyberhaven.Event.source.cloud_share_recipient.scope | String | The sharing scope. |
| Cyberhaven.Event.source.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share. |
| Cyberhaven.Event.source.cloud_share_recipient.role | String | The role of the cloud share recipient. |
| Cyberhaven.Event.source.printer.name | String | The name of the printer. |
| Cyberhaven.Event.source.printer.description | String | The description of the printer. |
| Cyberhaven.Event.source.printer.physical_location | String | The physical location of the printer. |
| Cyberhaven.Event.source.printer.server | String | The print server hostname. |
| Cyberhaven.Event.source.printer.share_name | String | The share name of the printer. |
| Cyberhaven.Event.source.printer.port | String | The port of the printer. |
| Cyberhaven.Event.source.printer.driver | String | The driver name of the printer. |
| Cyberhaven.Event.source.printer.is_local | Boolean | Whether the printer is local. |
| Cyberhaven.Event.source.printer.job_id | String | The print job ID. |
| Cyberhaven.Event.source.printer.connectivity | String | The connectivity type of the printer. |
| Cyberhaven.Event.source.removable_storage.id | String | The ID of the removable storage device. |
| Cyberhaven.Event.source.removable_storage.name | String | The name of the removable storage device. |
| Cyberhaven.Event.source.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage. |
| Cyberhaven.Event.source.removable_storage.vendor_id | String | The USB vendor ID of the removable storage. |
| Cyberhaven.Event.source.removable_storage.product_id | String | The USB product ID of the removable storage. |
| Cyberhaven.Event.source.im_message.sender | String | The sender of the IM message. |
| Cyberhaven.Event.source.im_message.recipient_users | String | The recipient users of the IM message. |
| Cyberhaven.Event.source.im_message.recipient_groups | String | The recipient groups of the IM message. |
| Cyberhaven.Event.source.im_message.domain | String | The domain of the IM message. |
| Cyberhaven.Event.source.im_message.workspace | String | The workspace of the IM message. |
| Cyberhaven.Event.source.source_code_repo.organization | String | The organization of the source code repository. |
| Cyberhaven.Event.source.source_code_repo.name | String | The name of the source code repository. |
| Cyberhaven.Event.source.source_code_repo.branch | String | The branch of the source code repository. |
| Cyberhaven.Event.source.source_code_repo.id | String | The ID of the source code repository. |
| Cyberhaven.Event.source.labels | String | The labels applied to the object. |
| Cyberhaven.Event.source.label_ids | String | The label IDs applied to the object. |
| Cyberhaven.Event.source.matched_policies | String | The list of DLP policies matched by the object. |
| Cyberhaven.Event.source.issues | String | The list of DLP issues detected on the object. |
| Cyberhaven.Event.source.outline | String | The outline description of the object. |
| Cyberhaven.Event.source.type | String | The endpoint type \(e.g. endpoint, removable_media\). |
| Cyberhaven.Event.source.domain | String | The domain of the object. |
| Cyberhaven.Event.source.discovered_at | Date | The timestamp when the object was first discovered. |
| Cyberhaven.Event.source.updated_at | Date | The timestamp when the object was last updated. |
| Cyberhaven.Event.source.update_event.id | String | The ID of the update event. |
| Cyberhaven.Event.source.update_event.action_kind | String | The action kind of the update event. |
| Cyberhaven.Event.source.update_event.timestamp | Date | The timestamp of the update event. |
| Cyberhaven.Event.source.update_event.user.id | String | The user ID in the update event. |
| Cyberhaven.Event.source.update_event.user.local_username | String | The local username in the update event. |
| Cyberhaven.Event.source.update_event.user.local_id | String | The local ID in the update event. |
| Cyberhaven.Event.source.version_id | String | The version ID of the object. |
| Cyberhaven.Event.source.cloud_connector.id | String | The ID of the cloud connector. |
| Cyberhaven.Event.source.cloud_connector.type | String | The type of cloud connector. |
| Cyberhaven.Event.source.cloud_connector.name | String | The name of the cloud connector. |
| Cyberhaven.Event.source.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector. |
| Cyberhaven.Event.source.cloud_connector.account_id | String | The account ID of the cloud connector. |
| Cyberhaven.Event.destination.id | String | The ID of the object. |
| Cyberhaven.Event.destination.display_name | String | The display name of the object. |
| Cyberhaven.Event.destination.datastore_id | String | The datastore ID associated with the object. |
| Cyberhaven.Event.destination.dataset_sensitivity | String | The sensitivity classification of the dataset. |
| Cyberhaven.Event.destination.dataset_ids | String | The list of dataset IDs associated with the object. |
| Cyberhaven.Event.destination.object_type | String | The object type \(e.g. file, removable_storage\). |
| Cyberhaven.Event.destination.state | String | The state of the object \(e.g. active\). |
| Cyberhaven.Event.destination.content.tags | String | The content classification tags. |
| Cyberhaven.Event.destination.content.attributes | String | The content attributes. |
| Cyberhaven.Event.destination.content.upload_filename | String | The upload filename of the content. |
| Cyberhaven.Event.destination.content.inspected | Boolean | Whether the content was inspected. |
| Cyberhaven.Event.destination.data.labels | String | The data classification labels. |
| Cyberhaven.Event.destination.data.label_ids | String | The data classification label IDs. |
| Cyberhaven.Event.destination.app.name | String | The name of the associated application. |
| Cyberhaven.Event.destination.app.description | String | The description of the associated application. |
| Cyberhaven.Event.destination.app.package_name | String | The package name of the associated application. |
| Cyberhaven.Event.destination.app.binary_path | String | The binary path of the associated application. |
| Cyberhaven.Event.destination.app.command_line | String | The command line of the associated application. |
| Cyberhaven.Event.destination.app.main_window_title | String | The main window title of the associated application. |
| Cyberhaven.Event.destination.file.name | String | The file name. |
| Cyberhaven.Event.destination.file.extension | String | The file extension. |
| Cyberhaven.Event.destination.file.size | Number | The file size \(bytes\). |
| Cyberhaven.Event.destination.file.md5_hash | String | The MD5 hash of the file. |
| Cyberhaven.Event.destination.file.sha256_hash | String | The SHA-256 hash of the file. |
| Cyberhaven.Event.destination.file.created_at | Date | The creation timestamp of the file. |
| Cyberhaven.Event.destination.file.modified_at | Date | The last modification timestamp of the file. |
| Cyberhaven.Event.destination.file.owner.name | String | The name of the file owner. |
| Cyberhaven.Event.destination.file.owner.id | String | The ID of the file owner. |
| Cyberhaven.Event.destination.local_file.id | String | The local file ID. |
| Cyberhaven.Event.destination.local_file.path | String | The local file system path. |
| Cyberhaven.Event.destination.network_share.hostname | String | The hostname of the network share. |
| Cyberhaven.Event.destination.network_share.path | String | The path of the network share. |
| Cyberhaven.Event.destination.email.id | String | The ID of the email. |
| Cyberhaven.Event.destination.email.from | String | The sender of the email. |
| Cyberhaven.Event.destination.email.to | String | The recipients of the email. |
| Cyberhaven.Event.destination.email.cc | String | The CC recipients of the email. |
| Cyberhaven.Event.destination.email.bcc | String | The BCC recipients of the email. |
| Cyberhaven.Event.destination.email.subject | String | The subject of the email. |
| Cyberhaven.Event.destination.email_attachment.id | String | The ID of the email attachment. |
| Cyberhaven.Event.destination.web.url | String | The URL of the web endpoint. |
| Cyberhaven.Event.destination.web.domain | String | The domain of the web endpoint. |
| Cyberhaven.Event.destination.web.category | String | The category of the web endpoint \(e.g. cloud_storage\). |
| Cyberhaven.Event.destination.web.download_url | String | The download URL of the web endpoint. |
| Cyberhaven.Event.destination.web.title | String | The page title of the web endpoint. |
| Cyberhaven.Event.destination.web.user_agent | String | The user-agent string of the web endpoint. |
| Cyberhaven.Event.destination.cloud_app.provider | String | The cloud provider \(e.g. google\). |
| Cyberhaven.Event.destination.cloud_app.name | String | The name of the cloud application. |
| Cyberhaven.Event.destination.cloud_app.user_name | String | The username in the cloud application. |
| Cyberhaven.Event.destination.cloud_app.user_email | String | The user email in the cloud application. |
| Cyberhaven.Event.destination.cloud_app.instance_id | String | The instance ID of the cloud application. |
| Cyberhaven.Event.destination.cloud_app.instance_name | String | The instance name of the cloud application. |
| Cyberhaven.Event.destination.cloud_file.id | String | The ID of the cloud file. |
| Cyberhaven.Event.destination.cloud_file.content_uri | String | The content URI of the cloud file. |
| Cyberhaven.Event.destination.cloud_file.path | String | The path of the cloud file. |
| Cyberhaven.Event.destination.cloud_share_recipient.scope | String | The sharing scope. |
| Cyberhaven.Event.destination.cloud_share_recipient.user_ids | String | The recipient user IDs of the cloud share. |
| Cyberhaven.Event.destination.cloud_share_recipient.role | String | The role of the cloud share recipient. |
| Cyberhaven.Event.destination.printer.name | String | The name of the printer. |
| Cyberhaven.Event.destination.printer.description | String | The description of the printer. |
| Cyberhaven.Event.destination.printer.physical_location | String | The physical location of the printer. |
| Cyberhaven.Event.destination.printer.server | String | The print server hostname. |
| Cyberhaven.Event.destination.printer.share_name | String | The share name of the printer. |
| Cyberhaven.Event.destination.printer.port | String | The port of the printer. |
| Cyberhaven.Event.destination.printer.driver | String | The driver name of the printer. |
| Cyberhaven.Event.destination.printer.is_local | Boolean | Whether the printer is local. |
| Cyberhaven.Event.destination.printer.job_id | String | The print job ID. |
| Cyberhaven.Event.destination.printer.connectivity | String | The connectivity type of the printer. |
| Cyberhaven.Event.destination.removable_storage.id | String | The ID of the removable storage device. |
| Cyberhaven.Event.destination.removable_storage.name | String | The name of the removable storage device. |
| Cyberhaven.Event.destination.removable_storage.usb_id | String | The USB vendor:product ID of the removable storage. |
| Cyberhaven.Event.destination.removable_storage.vendor_id | String | The USB vendor ID of the removable storage. |
| Cyberhaven.Event.destination.removable_storage.product_id | String | The USB product ID of the removable storage. |
| Cyberhaven.Event.destination.im_message.sender | String | The sender of the IM message. |
| Cyberhaven.Event.destination.im_message.recipient_users | String | The recipient users of the IM message. |
| Cyberhaven.Event.destination.im_message.recipient_groups | String | The recipient groups of the IM message. |
| Cyberhaven.Event.destination.im_message.domain | String | The domain of the IM message. |
| Cyberhaven.Event.destination.im_message.workspace | String | The workspace of the IM message. |
| Cyberhaven.Event.destination.source_code_repo.organization | String | The organization of the source code repository. |
| Cyberhaven.Event.destination.source_code_repo.name | String | The name of the source code repository. |
| Cyberhaven.Event.destination.source_code_repo.branch | String | The branch of the source code repository. |
| Cyberhaven.Event.destination.source_code_repo.id | String | The ID of the source code repository. |
| Cyberhaven.Event.destination.labels | String | The labels applied to the object. |
| Cyberhaven.Event.destination.label_ids | String | The label IDs applied to the object. |
| Cyberhaven.Event.destination.matched_policies | String | The list of DLP policies matched by the object. |
| Cyberhaven.Event.destination.issues | String | The list of DLP issues detected on the object. |
| Cyberhaven.Event.destination.outline | String | The outline description of the object. |
| Cyberhaven.Event.destination.type | String | The endpoint type \(e.g. endpoint, removable_media\). |
| Cyberhaven.Event.destination.domain | String | The domain of the object. |
| Cyberhaven.Event.destination.discovered_at | Date | The timestamp when the object was first discovered. |
| Cyberhaven.Event.destination.updated_at | Date | The timestamp when the object was last updated. |
| Cyberhaven.Event.destination.update_event.id | String | The ID of the update event. |
| Cyberhaven.Event.destination.update_event.action_kind | String | The action kind of the update event. |
| Cyberhaven.Event.destination.update_event.timestamp | Date | The timestamp of the update event. |
| Cyberhaven.Event.destination.update_event.user.id | String | The user ID in the update event. |
| Cyberhaven.Event.destination.update_event.user.local_username | String | The local username in the update event. |
| Cyberhaven.Event.destination.update_event.user.local_id | String | The local ID in the update event. |
| Cyberhaven.Event.destination.version_id | String | The version ID of the object. |
| Cyberhaven.Event.destination.cloud_connector.id | String | The ID of the cloud connector. |
| Cyberhaven.Event.destination.cloud_connector.type | String | The type of cloud connector. |
| Cyberhaven.Event.destination.cloud_connector.name | String | The name of the cloud connector. |
| Cyberhaven.Event.destination.cloud_connector.onboarding_account | String | The onboarding account of the cloud connector. |
| Cyberhaven.Event.destination.cloud_connector.account_id | String | The account ID of the cloud connector. |

#### Command example

```!cyberhaven-event-details-get event_ids="evt_start_001abc"```

#### Context Example

```json
{
    "Cyberhaven": {
        "Event": [
            {
                "id": "evt_start_001abc",
                "timestamp": "2026-01-15T10:28:45Z",
                "action": {
                    "kind": "copy",
                    "blocked": false,
                    "data_size": 2048576,
                    "content": {
                        "tags": [
                            "pii",
                            "confidential"
                        ],
                        "attributes": {
                            "word_count": 1500,
                            "page_count": 3,
                            "record_count": 250,
                            "sensitivity_score": 95
                        },
                        "upload_filename": "employee_salaries_2026.xlsx",
                        "custom_data": {
                            "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        },
                        "inspected": true
                    },
                    "sensor_kind": "endpoint",
                    "hostname": "WORKSTATION-NYC-042",
                    "machine_serial_number": "C02XK1JFHV2R",
                    "custom_data": {
                        "os_version": "Windows 11 22H2"
                    },
                    "ip_address": "192.168.1.100",
                    "device_type": "managed",
                    "temporary_blocked": false,
                    "fail_close_statuses": [
                        {
                            "temporary_blocked": false,
                            "dlp_api_status": "SUCCESS",
                            "dlp_precondition": "DLP_PRECONDITION_MET",
                            "action_status": "ACTION_STATUS_COMPLETED"
                        }
                    ],
                    "process_id": 4821,
                    "parent_process_id": 1024
                },
                "user": {
                    "id": "usr_john_doe_001",
                    "local_username": "john.doe",
                    "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                    "custom_data": {
                        "session_id": "sess_20260115_001"
                    }
                },
                "source": {
                    "id": "src_local_001abc",
                    "display_name": "employee_salaries_2026.xlsx",
                    "datastore_id": "dstore_endpoint_01",
                    "dataset_sensitivity": "sensitivity_high",
                    "dataset_ids": [
                        "ds_hr_confidential"
                    ],
                    "object_type": "file",
                    "state": "active",
                    "content": {
                        "tags": [
                            "pii",
                            "confidential"
                        ],
                        "attributes": {
                            "record_count": 250
                        },
                        "upload_filename": "employee_salaries_2026.xlsx",
                        "custom_data": {
                            "classification": "confidential",
                            "last_scan": "2026-01-10T09:00:00Z",
                            "scan_result": "contains_pii",
                            "owner_department": "HR"
                        },
                        "inspected": true
                    },
                    "data": {
                        "labels": [
                            "PII",
                            "Confidential",
                            "HR Data"
                        ],
                        "label_ids": [
                            "lbl_pii",
                            "lbl_confidential"
                        ]
                    },
                    "app": {
                        "name": "Microsoft Excel",
                        "description": "Microsoft Office Spreadsheet Application",
                        "package_name": "com.microsoft.excel",
                        "binary_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                        "command_line": "\"EXCEL.EXE\" /e",
                        "main_window_title": "employee_salaries_2026.xlsx - Excel",
                        "custom_data": {
                            "version": "16.0.17126.20132",
                            "publisher": "Microsoft Corporation",
                            "signed": "true",
                            "install_date": "2023-06-01"
                        }
                    },
                    "file": {
                        "name": "employee_salaries_2026.xlsx",
                        "extension": "xlsx",
                        "size": 2048576,
                        "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "custom_data": {
                            "creator": "john.doe",
                            "last_modified_by": "jane.smith",
                            "revision": "3"
                        },
                        "created_at": "2026-01-10T09:00:00Z",
                        "modified_at": "2026-01-15T08:30:00Z",
                        "owner": {
                            "name": "john.doe",
                            "id": "usr_john_doe_001"
                        }
                    },
                    "local_file": {
                        "id": "lf_001abc",
                        "path": "C:\\Users\\john.doe\\Documents\\HR\\employee_salaries_2026.xlsx"
                    },
                    "network_share": {
                        "hostname": "FILESERVER-01",
                        "path": "\\\\FILESERVER-01\\HR\\Compensation",
                        "custom_data": {
                            "share_type": "SMB",
                            "mount_point": "Z:"
                        }
                    },
                    "email": {
                        "id": "email_src_001",
                        "from": "john.doe@company.com",
                        "to": [
                            "personal@gmail.com"
                        ],
                        "cc": [
                            "backup@gmail.com"
                        ],
                        "bcc": [
                            "archive@gmail.com"
                        ],
                        "subject": "Salary Data Backup",
                        "custom_data": {
                            "message_id": "<20260115102845.001@company.com>"
                        }
                    },
                    "email_attachment": {
                        "id": "attach_src_001",
                        "custom_data": {
                            "attachment_index": "0",
                            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        }
                    },
                    "web": {
                        "url": "https://drive.google.com/upload",
                        "domain": "drive.google.com",
                        "category": "cloud_storage",
                        "download_url": "https://drive.google.com/file/d/1abc123/view",
                        "title": "Google Drive - Upload",
                        "custom_data": {
                            "referrer": "https://drive.google.com/"
                        },
                        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    },
                    "cloud_app": {
                        "provider": "google",
                        "name": "google_drive",
                        "user_name": "john.doe",
                        "user_email": "john.doe@personal.com",
                        "custom_data": {
                            "tenant_id": "tenant_google_001",
                            "app_version": "2026.1"
                        },
                        "instance_id": "gdrive_inst_001",
                        "instance_name": "Personal Google Drive"
                    },
                    "cloud_file": {
                        "id": "cf_src_001",
                        "content_uri": "https://drive.google.com/file/d/1abc123/content",
                        "path": "/My Drive/HR Data/employee_salaries_2026.xlsx",
                        "custom_data": {
                            "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "revision_id": "rev_001"
                        }
                    },
                    "cloud_share_recipient": {
                        "scope": "share_external",
                        "user_ids": [
                            "external_user_001"
                        ],
                        "role": "role_viewer",
                        "custom_data": {
                            "expiry_date": "2026-12-31"
                        }
                    },
                    "printer": {
                        "name": "HP LaserJet Pro M404n",
                        "description": "Office Laser Printer - Floor 3",
                        "physical_location": "3rd Floor Copy Room",
                        "server": "PRINTSERVER-01",
                        "share_name": "HP-LaserJet-3F",
                        "port": "IP_192.168.1.200",
                        "driver": "HP LaserJet Pro M404n PCL 6",
                        "is_local": false,
                        "job_id": "print_job_4521",
                        "custom_data": {
                            "pages_printed": "12"
                        },
                        "connectivity": "network"
                    },
                    "removable_storage": {
                        "id": "usb_src_001",
                        "name": "SanDisk Ultra 64GB",
                        "usb_id": "usb_0781_5581",
                        "vendor_id": "0781",
                        "product_id": "5581",
                        "custom_data": {
                            "serial_number": "4C530001041120115283"
                        }
                    },
                    "im_message": {
                        "sender": "john.doe@company.com",
                        "recipient_users": [
                            "personal.contact@gmail.com"
                        ],
                        "recipient_groups": [
                            "external-group-001"
                        ],
                        "domain": "teams.microsoft.com",
                        "workspace": "Personal Chat",
                        "custom_data": {
                            "message_id": "msg_001abc",
                            "platform": "teams"
                        }
                    },
                    "source_code_repo": {
                        "organization": "company-org",
                        "name": "hr-data-scripts",
                        "custom_data": {
                            "visibility": "private"
                        },
                        "branch": "main",
                        "id": "repo_001"
                    },
                    "labels": [
                        "PII",
                        "Confidential"
                    ],
                    "label_ids": [
                        "lbl_pii",
                        "lbl_confidential"
                    ],
                    "matched_policies": [
                        {
                            "policy_type": "dlp",
                            "id": "pol_dlp_hr_001",
                            "version": 3,
                            "definition_rule_ids": [
                                "rule_pii_detection",
                                "rule_confidential_data"
                            ],
                            "action_rule_id": "action_rule_block",
                            "matched_at": "2026-01-15T10:28:45Z"
                        }
                    ],
                    "issues": [
                        {
                            "id": "issue_001abc",
                            "policy_type": "dlp",
                            "matched_policy_id": "pol_dlp_hr_001",
                            "policy_action_rule_id": "action_rule_block",
                            "severity": "issue_severity_high",
                            "detected_at": "2026-01-15T10:28:45Z"
                        }
                    ],
                    "custom_data": {
                        "data_classification": "confidential"
                    },
                    "outline": "Spreadsheet containing employee salary and compensation data for 250 employees in the Engineering department.",
                    "type": "website",
                    "domain": "company.com",
                    "discovered_at": "2026-01-10T09:00:00Z",
                    "updated_at": "2026-01-15T10:28:45Z",
                    "update_event": {
                        "id": "upd_evt_001",
                        "action_kind": "read",
                        "timestamp": "2026-01-15T10:28:45Z",
                        "user": {
                            "id": "usr_john_doe_001",
                            "local_username": "john.doe",
                            "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                            "custom_data": {
                                "session_id": "sess_20260115_001",
                                "ad_group": "Domain Users"
                            }
                        }
                    },
                    "version_id": "ver_001abc",
                    "cloud_connector": {
                        "id": "cc_snowflake_001",
                        "type": "snowflake",
                        "name": "Company Snowflake Integration",
                        "onboarding_account": "snowflake-admin@company.com",
                        "account_id": "sf_snowflake_001"
                    }
                },
                "destination": {
                    "id": "dst_usb_001abc",
                    "display_name": "SanDisk Ultra 64GB (E:)",
                    "datastore_id": "dstore_usb_01",
                    "dataset_sensitivity": "sensitivity_unspecified",
                    "dataset_ids": [
                        "ds_removable_default"
                    ],
                    "object_type": "removable_storage",
                    "state": "active",
                    "content": {
                        "tags": [
                            "external",
                            "removable"
                        ],
                        "attributes": {
                            "file_count": 1
                        },
                        "upload_filename": "employee_salaries_2026.xlsx",
                        "custom_data": {
                            "destination_path": "E:\\Backup\\HR",
                            "overwrite": "false"
                        },
                        "inspected": true
                    },
                    "data": {
                        "labels": [
                            "External Storage",
                            "Removable Media"
                        ],
                        "label_ids": [
                            "lbl_external_storage",
                            "lbl_removable_media"
                        ]
                    },
                    "app": {
                        "name": "Windows Explorer",
                        "description": "Windows File Explorer",
                        "package_name": "com.microsoft.explorer",
                        "binary_path": "C:\\Windows\\explorer.exe",
                        "command_line": "explorer.exe /select,\"E:\\Backup\\HR\\employee_salaries_2026.xlsx\"",
                        "main_window_title": "E:\\Backup\\HR",
                        "custom_data": {
                            "version": "10.0.22621.1",
                            "elevated": "false"
                        }
                    },
                    "file": {
                        "name": "employee_salaries_2026.xlsx",
                        "extension": "xlsx",
                        "size": 2048576,
                        "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "custom_data": {
                            "destination_created": "true",
                            "is_copy": "true"
                        },
                        "created_at": "2026-01-15T10:28:50Z",
                        "modified_at": "2026-01-15T10:28:50Z",
                        "owner": {
                            "name": "john.doe",
                            "id": "usr_john_doe_001"
                        }
                    },
                    "local_file": {
                        "id": "lf_dst_001",
                        "path": "E:\\Backup\\HR\\employee_salaries_2026.xlsx"
                    },
                    "network_share": {
                        "hostname": "FILESERVER-01",
                        "path": "\\\\FILESERVER-01\\Backup\\HR",
                        "custom_data": {
                            "share_type": "SMB"
                        }
                    },
                    "email": {
                        "id": "email_dst_001",
                        "from": "john.doe@company.com",
                        "to": [
                            "personal@gmail.com"
                        ],
                        "cc": [
                            "backup@gmail.com"
                        ],
                        "bcc": [
                            "archive@gmail.com"
                        ],
                        "subject": "Salary Data Backup",
                        "custom_data": {
                            "message_id": "<20260115102845.001@company.com>"
                        }
                    },
                    "email_attachment": {
                        "id": "attach_dst_001",
                        "custom_data": {
                            "attachment_index": "0"
                        }
                    },
                    "web": {
                        "url": "https://drive.google.com/upload/resumable",
                        "domain": "drive.google.com",
                        "category": "cloud_storage",
                        "download_url": "https://drive.google.com/file/d/1abc123/view",
                        "title": "Google Drive - Upload Complete",
                        "custom_data": {
                            "upload_session_id": "upload_sess_001"
                        },
                        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    },
                    "cloud_app": {
                        "provider": "google",
                        "name": "google_drive",
                        "user_name": "john.doe",
                        "user_email": "john.doe@personal.com",
                        "custom_data": {
                            "upload_complete": "true"
                        },
                        "instance_id": "gdrive_inst_001",
                        "instance_name": "Personal Google Drive"
                    },
                    "cloud_file": {
                        "id": "cf_dst_001",
                        "content_uri": "https://drive.google.com/file/d/1abc123/content",
                        "path": "/My Drive/HR Backup/employee_salaries_2026.xlsx",
                        "custom_data": {
                            "upload_timestamp": "2026-01-15T10:29:00Z",
                            "file_id": "1abc123xyz",
                            "revision_id": "rev_001"
                        }
                    },
                    "cloud_share_recipient": {
                        "scope": "share_external",
                        "user_ids": [
                            "external_user_001",
                            "external_user_002"
                        ],
                        "role": "role_viewer",
                        "custom_data": {
                            "expiry_date": "2026-12-31",
                            "notify_on_access": "true"
                        }
                    },
                    "printer": {
                        "name": "HP LaserJet Pro M404n",
                        "description": "Office Laser Printer - Floor 3",
                        "physical_location": "3rd Floor Copy Room",
                        "server": "PRINTSERVER-01",
                        "share_name": "HP-LaserJet-3F",
                        "port": "IP_192.168.1.200",
                        "driver": "HP LaserJet Pro M404n PCL 6",
                        "is_local": false,
                        "job_id": "print_job_4521",
                        "custom_data": {
                            "pages_printed": "12"
                        },
                        "connectivity": "network"
                    },
                    "removable_storage": {
                        "id": "usb_dst_001",
                        "name": "SanDisk Ultra 64GB",
                        "usb_id": "usb_0781_5581",
                        "vendor_id": "0781",
                        "product_id": "5581",
                        "custom_data": {
                            "serial_number": "4C530001041120115283",
                            "drive_letter": "E"
                        }
                    },
                    "im_message": {
                        "sender": "john.doe@company.com",
                        "recipient_users": [
                            "personal.contact@gmail.com"
                        ],
                        "recipient_groups": [
                            "external-group-001"
                        ],
                        "domain": "teams.microsoft.com",
                        "workspace": "Personal Chat",
                        "custom_data": {
                            "message_id": "msg_dst_001"
                        }
                    },
                    "source_code_repo": {
                        "organization": "personal-org",
                        "name": "personal-backup-repo",
                        "custom_data": {
                            "visibility": "private"
                        },
                        "branch": "main",
                        "id": "repo_dst_001"
                    },
                    "labels": [
                        "External Storage",
                        "Removable Media"
                    ],
                    "label_ids": [
                        "lbl_external_storage",
                        "lbl_removable_media"
                    ],
                    "matched_policies": [
                        {
                            "policy_type": "dlp",
                            "id": "pol_dlp_removable_001",
                            "version": 2,
                            "definition_rule_ids": [
                                "rule_removable_media_write"
                            ],
                            "action_rule_id": "action_rule_alert",
                            "matched_at": "2026-01-15T10:28:50Z"
                        }
                    ],
                    "issues": [
                        {
                            "id": "issue_dst_001",
                            "policy_type": "dlp",
                            "matched_policy_id": "pol_dlp_removable_001",
                            "policy_action_rule_id": "action_rule_alert",
                            "severity": "issue_severity_high",
                            "detected_at": "2026-01-15T10:28:50Z"
                        }
                    ],
                    "custom_data": {
                        "endpoint_risk": "high",
                        "device_approved": "false",
                        "destination_type": "removable_media",
                        "risk_assessment": "critical",
                        "flagged_by": "dlp_engine"
                    },
                    "outline": "SanDisk USB removable storage device used as unauthorized destination for confidential HR data transfer.",
                    "type": "cloud_apps",
                    "domain": "company.com",
                    "discovered_at": "2026-01-15T10:28:45Z",
                    "updated_at": "2026-01-15T10:28:50Z",
                    "update_event": {
                        "id": "upd_evt_dst_001",
                        "action_kind": "write",
                        "timestamp": "2026-01-15T10:28:50Z",
                        "user": {
                            "id": "usr_john_doe_001",
                            "local_username": "john.doe",
                            "local_id": "S-1-5-21-3623811015-3361044348-030300820-1013",
                            "custom_data": {
                                "session_id": "sess_20260115_001",
                                "ad_group": "Domain Users"
                            }
                        }
                    },
                    "version_id": "ver_dst_001",
                    "cloud_connector": {
                        "id": "cc_salesforce_001",
                        "type": "salesforce",
                        "name": "Company Salesforce Integration",
                        "onboarding_account": "admin@company.com",
                        "account_id": "sf_acct_001"
                    }
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Cyberhaven Event Details
>
>|ID|Time|User|Action|Source|Destination|
>|---|---|---|---|---|---|
>| evt_start_001abc | 2026-01-15T10:28:45Z | ***id***: usr_john_doe_001<br>***local_username***: john.doe<br>***local_id***: S-1-5-21-3623811015-3361044348-030300820-1013<br>**custom_data**:<br> ***session_id***: sess_20260115_001 | ***kind***: copy<br>***blocked***: false<br>***data_size***: 2048576<br>**content**:<br> **tags**:<br>  ***values***: pii, confidential<br> **attributes**:<br>  ***word_count***: 1500<br>  ***page_count***: 3<br>  ***record_count***: 250<br>  ***sensitivity_score***: 95<br> ***upload_filename***: employee_salaries_2026.xlsx<br> **custom_data**:<br>  ***mime_type***: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet<br> ***inspected***: true<br>***sensor_kind***: endpoint<br>***hostname***: WORKSTATION-NYC-042<br>***machine_serial_number***: C02XK1JFHV2R<br>**custom_data**:<br> ***os_version***: Windows 11 22H2<br>***ip_address***: 192.168.1.100<br>***device_type***: managed<br>***temporary_blocked***: false<br>**fail_close_statuses**:<br> **-** ***temporary_blocked***: false<br>  ***dlp_api_status***: SUCCESS<br>  ***dlp_precondition***: DLP_PRECONDITION_MET<br>  ***action_status***: ACTION_STATUS_COMPLETED<br>***process_id***: 4821<br>***parent_process_id***: 1024 | ***id***: src_local_001abc<br>***display_name***: employee_salaries_2026.xlsx<br>***datastore_id***: dstore_endpoint_01<br>***dataset_sensitivity***: sensitivity_high<br>**dataset_ids**:<br> ***values***: ds_hr_confidential<br>***object_type***: file<br>***state***: active<br>**content**:<br> **tags**:<br>  ***values***: pii, confidential<br> **attributes**:<br>  ***record_count***: 250<br> ***upload_filename***: employee_salaries_2026.xlsx<br> **custom_data**:<br>  ***classification***: confidential<br>  ***last_scan***: 2026-01-10T09:00:00Z<br>  ***scan_result***: contains_pii<br>  ***owner_department***: HR<br> ***inspected***: true<br>**data**:<br> **labels**:<br>  ***values***: PII, Confidential, HR Data<br> **label_ids**:<br>  ***values***: lbl_pii, lbl_confidential<br>**app**:<br> ***name***: Microsoft Excel<br> ***description***: Microsoft Office Spreadsheet Application<br> ***package_name***: com.microsoft.excel<br> ***binary_path***: C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE<br> ***command_line***: "EXCEL.EXE" /e<br> ***main_window_title***: employee_salaries_2026.xlsx - Excel<br> **custom_data**:<br>  ***version***: 16.0.17126.20132<br>  ***publisher***: Microsoft Corporation<br>  ***signed***: true<br>  ***install_date***: 2023-06-01<br>**file**:<br> ***name***: employee_salaries_2026.xlsx<br> ***extension***: xlsx<br> ***size***: 2048576<br> ***md5_hash***: d41d8cd98f00b204e9800998ecf8427e<br> ***sha256_hash***: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855<br> **custom_data**:<br>  ***creator***: john.doe<br>  ***last_modified_by***: jane.smith<br>  ***revision***: 3<br> ***created_at***: 2026-01-10T09:00:00Z<br> ***modified_at***: 2026-01-15T08:30:00Z<br> **owner**:<br>  ***name***: john.doe<br>  ***id***: usr_john_doe_001<br>**local_file**:<br> ***id***: lf_001abc<br> ***path***: C:\Users\john.doe\Documents\HR\employee_salaries_2026.xlsx<br>**network_share**:<br> ***hostname***: FILESERVER-01<br> ***path***: \\FILESERVER-01\HR\Compensation<br> **custom_data**:<br>  ***share_type***: SMB<br>  ***mount_point***: Z:<br>**email**:<br> ***id***: email_src_001<br> ***from***: <john.doe@company.com><br> **to**:<br>  ***values***: <personal@gmail.com><br> **cc**:<br>  ***values***: <backup@gmail.com><br> **bcc**:<br>  ***values***: <archive@gmail.com><br> ***subject***: Salary Data Backup<br> **custom_data**:<br>  ***message_id***: <20260115102845.001@company.com><br>**email_attachment**:<br> ***id***: attach_src_001<br> **custom_data**:<br>  ***attachment_index***: 0<br>  ***content_type***: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet<br>**web**:<br> ***url***: <https://drive.google.com/upload><br> ***domain***: drive.google.com<br> ***category***: cloud_storage<br> ***download_url***: <https://drive.google.com/file/d/1abc123/view><br> ***title***: Google Drive - Upload<br> **custom_data**:<br>  ***referrer***: <https://drive.google.com/><br> ***user_agent***: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>**cloud_app**:<br> ***provider***: google<br> ***name***: google_drive<br> ***user_name***: john.doe<br> ***user_email***: <john.doe@personal.com><br> **custom_data**:<br>  ***tenant_id***: tenant_google_001<br>  ***app_version***: 2026.1<br> ***instance_id***: gdrive_inst_001<br> ***instance_name***: Personal Google Drive<br>**cloud_file**:<br> ***id***: cf_src_001<br> ***content_uri***: <https://drive.google.com/file/d/1abc123/content><br> ***path***: /My Drive/HR Data/employee_salaries_2026.xlsx<br> **custom_data**:<br>  ***mime_type***: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet<br>  ***revision_id***: rev_001<br>**cloud_share_recipient**:<br> ***scope***: share_external<br> **user_ids**:<br>  ***values***: external_user_001<br> ***role***: role_viewer<br> **custom_data**:<br>  ***expiry_date***: 2026-12-31<br>**printer**:<br> ***name***: HP LaserJet Pro M404n<br> ***description***: Office Laser Printer - Floor 3<br> ***physical_location***: 3rd Floor Copy Room<br> ***server***: PRINTSERVER-01<br> ***share_name***: HP-LaserJet-3F<br> ***port***: IP_192.168.1.200<br> ***driver***: HP LaserJet Pro M404n PCL 6<br> ***is_local***: false<br> ***job_id***: print_job_4521<br> **custom_data**:<br>  ***pages_printed***: 12<br> ***connectivity***: network<br>**removable_storage**:<br> ***id***: usb_src_001<br> ***name***: SanDisk Ultra 64GB<br> ***usb_id***: usb_0781_5581<br> ***vendor_id***: 0781<br> ***product_id***: 5581<br> **custom_data**:<br>  ***serial_number***: 4C530001041120115283<br>**im_message**:<br> ***sender***: <john.doe@company.com><br> **recipient_users**:<br>  ***values***: <personal.contact@gmail.com><br> **recipient_groups**:<br>  ***values***: external-group-001<br> ***domain***: teams.microsoft.com<br> ***workspace***: Personal Chat<br> **custom_data**:<br>  ***message_id***: msg_001abc<br>  ***platform***: teams<br>**source_code_repo**:<br> ***organization***: company-org<br> ***name***: hr-data-scripts<br> **custom_data**:<br>  ***visibility***: private<br> ***branch***: main<br> ***id***: repo_001<br>**labels**:<br> ***values***: PII, Confidential<br>**label_ids**:<br> ***values***: lbl_pii, lbl_confidential<br>**matched_policies**:<br> **-** ***policy_type***: dlp<br>  ***id***: pol_dlp_hr_001<br>  ***version***: 3<br>  **definition_rule_ids**:<br>   ***values***: rule_pii_detection, rule_confidential_data<br> ***action_rule_id***: action_rule_block<br>  ***matched_at***: 2026-01-15T10:28:45Z<br>**issues**:<br> **-** ***id***: issue_001abc<br>  ***policy_type***: dlp<br>  ***matched_policy_id***: pol_dlp_hr_001<br>  ***policy_action_rule_id***: action_rule_block<br>  ***severity***: issue_severity_high<br>  ***detected_at***: 2026-01-15T10:28:45Z<br>**custom_data**:<br> ***data_classification***: confidential<br>***outline***: Spreadsheet containing employee salary and compensation data for 250 employees in the Engineering department.<br>***type***: website<br>***domain***: company.com<br>***discovered_at***: 2026-01-10T09:00:00Z<br>***updated_at***: 2026-01-15T10:28:45Z<br>**update_event**:<br> ***id***: upd_evt_001<br> ***action_kind***: read<br> ***timestamp***: 2026-01-15T10:28:45Z<br> **user**:<br>  ***id***: usr_john_doe_001<br>  ***local_username***: john.doe<br>  ***local_id***: S-1-5-21-3623811015-3361044348-030300820-1013<br>  **custom_data**:<br>   ***session_id***: sess_20260115_001<br>   ***ad_group***: Domain Users<br>***version_id***: ver_001abc<br>**cloud_connector**:<br> ***id***: cc_snowflake_001<br> ***type***: snowflake<br> ***name***: Company Snowflake Integration<br> ***onboarding_account***: <snowflake-admin@company.com><br> ***account_id***: sf_snowflake_001 | ***id***: dst_usb_001abc<br>***display_name***: SanDisk Ultra 64GB (E:)<br>***datastore_id***: dstore_usb_01<br>***dataset_sensitivity***: sensitivity_unspecified<br>**dataset_ids**:<br> ***values***: ds_removable_default<br>***object_type***: removable_storage<br>***state***: active<br>**content**:<br> **tags**:<br>  ***values***: external, removable<br> **attributes**:<br>  ***file_count***: 1<br> ***upload_filename***: employee_salaries_2026.xlsx<br> **custom_data**:<br>  ***destination_path***: E:\Backup\HR<br>  ***overwrite***: false<br> ***inspected***: true<br>**data**:<br> **labels**:<br>  ***values***: External Storage, Removable Media<br> **label_ids**:<br>  ***values***: lbl_external_storage, lbl_removable_media<br>**app**:<br> ***name***: Windows Explorer<br> ***description***: Windows File Explorer<br> ***package_name***: com.microsoft.explorer<br> ***binary_path***: C:\Windows\explorer.exe<br> ***command_line***: explorer.exe /select,"E:\Backup\HR\employee_salaries_2026.xlsx"<br> ***main_window_title***: E:\Backup\HR<br> **custom_data**:<br>  ***version***: 10.0.22621.1<br>  ***elevated***: false<br>**file**:<br> ***name***: employee_salaries_2026.xlsx<br> ***extension***: xlsx<br> ***size***: 2048576<br> ***md5_hash***: d41d8cd98f00b204e9800998ecf8427e<br> ***sha256_hash***: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855<br> **custom_data**:<br>  ***destination_created***: true<br>  ***is_copy***: true<br> ***created_at***: 2026-01-15T10:28:50Z<br> ***modified_at***: 2026-01-15T10:28:50Z<br> **owner**:<br>  ***name***: john.doe<br>  ***id***: usr_john_doe_001<br>**local_file**:<br> ***id***: lf_dst_001<br> ***path***: E:\Backup\HR\employee_salaries_2026.xlsx<br>**network_share**:<br> ***hostname***: FILESERVER-01<br> ***path***: \\FILESERVER-01\Backup\HR<br> **custom_data**:<br>  ***share_type***: SMB<br>**email**:<br> ***id***: email_dst_001<br> ***from***: <john.doe@company.com><br> **to**:<br>  ***values***: <personal@gmail.com><br> **cc**:<br>  ***values***: <backup@gmail.com><br> **bcc**:<br>  ***values***: <archive@gmail.com><br> ***subject***: Salary Data Backup<br> **custom_data**:<br>  ***message_id***: <20260115102845.001@company.com><br>**email_attachment**:<br> ***id***: attach_dst_001<br> **custom_data**:<br>  ***attachment_index***: 0<br>**web**:<br> ***url***: <https://drive.google.com/upload/resumable><br> ***domain***: drive.google.com<br> ***category***: cloud_storage<br> ***download_url***: <https://drive.google.com/file/d/1abc123/view><br> ***title***: Google Drive - Upload Complete<br> **custom_data**:<br>  ***upload_session_id***: upload_sess_001<br> ***user_agent***: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>**cloud_app**:<br> ***provider***: google<br> ***name***: google_drive<br> ***user_name***: john.doe<br> ***user_email***: <john.doe@personal.com><br> **custom_data**:<br>  ***upload_complete***: true<br> ***instance_id***: gdrive_inst_001<br> ***instance_name***: Personal Google Drive<br>**cloud_file**:<br> ***id***: cf_dst_001<br> ***content_uri***: <https://drive.google.com/file/d/1abc123/content><br> ***path***: /My Drive/HR Backup/employee_salaries_2026.xlsx<br> **custom_data**:<br>  ***upload_timestamp***: 2026-01-15T10:29:00Z<br>  ***file_id***: 1abc123xyz<br>  ***revision_id***: rev_001<br>**cloud_share_recipient**:<br> ***scope***: share_external<br> **user_ids**:<br>  ***values***: external_user_001, external_user_002<br> ***role***: role_viewer<br> **custom_data**:<br>  ***expiry_date***: 2026-12-31<br>  ***notify_on_access***: true<br>**printer**:<br> ***name***: HP LaserJet Pro M404n<br> ***description***: Office Laser Printer - Floor 3<br> ***physical_location***: 3rd Floor Copy Room<br> ***server***: PRINTSERVER-01<br> ***share_name***: HP-LaserJet-3F<br> ***port***: IP_192.168.1.200<br> ***driver***: HP LaserJet Pro M404n PCL 6<br> ***is_local***: false<br> ***job_id***: print_job_4521<br> **custom_data**:<br>  ***pages_printed***: 12<br> ***connectivity***: network<br>**removable_storage**:<br> ***id***: usb_dst_001<br> ***name***: SanDisk Ultra 64GB<br> ***usb_id***: usb_0781_5581<br> ***vendor_id***: 0781<br> ***product_id***: 5581<br> **custom_data**:<br>  ***serial_number***: 4C530001041120115283<br>  ***drive_letter***: E<br>**im_message**:<br> ***sender***: <john.doe@company.com><br> **recipient_users**:<br>  ***values***: <personal.contact@gmail.com><br> **recipient_groups**:<br>  ***values***: external-group-001<br> ***domain***: teams.microsoft.com<br> ***workspace***: Personal Chat<br> **custom_data**:<br>  ***message_id***: msg_dst_001<br>**source_code_repo**:<br> ***organization***: personal-org<br> ***name***: personal-backup-repo<br> **custom_data**:<br>  ***visibility***: private<br> ***branch***: main<br> ***id***: repo_dst_001<br>**labels**:<br> ***values***: External Storage, Removable Media<br>**label_ids**:<br> ***values***: lbl_external_storage, lbl_removable_media<br>**matched_policies**:<br> **-** ***policy_type***: dlp<br>  ***id***: pol_dlp_removable_001<br>  ***version***: 2<br>  **definition_rule_ids**:<br>   ***values***: rule_removable_media_write<br> ***action_rule_id***: action_rule_alert<br>  ***matched_at***: 2026-01-15T10:28:50Z<br>**issues**:<br> **-** ***id***: issue_dst_001<br>  ***policy_type***: dlp<br>  ***matched_policy_id***: pol_dlp_removable_001<br>  ***policy_action_rule_id***: action_rule_alert<br>  ***severity***: issue_severity_high<br>  ***detected_at***: 2026-01-15T10:28:50Z<br>**custom_data**:<br> ***endpoint_risk***: high<br> ***device_approved***: false<br> ***destination_type***: removable_media<br> ***risk_assessment***: critical<br> ***flagged_by***: dlp_engine<br>***outline***: SanDisk USB removable storage device used as unauthorized destination for confidential HR data transfer.<br>***type***: cloud_apps<br>***domain***: company.com<br>***discovered_at***: 2026-01-15T10:28:45Z<br>***updated_at***: 2026-01-15T10:28:50Z<br>**update_event**:<br> ***id***: upd_evt_dst_001<br> ***action_kind***: write<br> ***timestamp***: 2026-01-15T10:28:50Z<br> **user**:<br>  ***id***: usr_john_doe_001<br>  ***local_username***: john.doe<br>  ***local_id***: S-1-5-21-3623811015-3361044348-030300820-1013<br>  **custom_data**:<br>   ***session_id***: sess_20260115_001<br>   ***ad_group***: Domain Users<br>***version_id***: ver_dst_001<br>**cloud_connector**:<br> ***id***: cc_salesforce_001<br> ***type***: salesforce<br> ***name***: Company Salesforce Integration<br> ***onboarding_account***: <admin@company.com><br> ***account_id***: sf_acct_001 |

### cyberhaven-event-lineage-get

***
Retrieves the data lineage chain between two Cyberhaven event IDs.

#### Base Command

`cyberhaven-event-lineage-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_event_id | Provide the UUID of the first event in the chain. | Required |
| end_event_id | Provide the UUID of the last event in the chain. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberhaven.EventLineage.resources | String | The list of events ID in order. |

#### Command example

```!cyberhaven-event-lineage-get start_event_id="evt-001" end_event_id="evt-003"```

#### Context Example

```json
{
    "Cyberhaven": {
        "EventLineage": [
            {
                "resources": [
                    "evt-001",
                    "evt-002",
                    "evt-003"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Event Lineage: evt-001 to evt-003
>
>|Number|ID|
>|---|---|
>| 1 | evt-001 |
>| 2 | evt-002 |
>| 3 | evt-003 |

## Troubleshoot

### Getting a Connection Error

**Summary:**
While running Test Connectivity, it fails with an error message similar to:
`Failed to execute test-module command. Error: Verify that the server URL parameter is correct and that you have access to the server from your host.`

**Troubleshooting:**

- Verify the **Server URL** field is correctly formatted (e.g., `https://example.cyberhaven.io`) with no trailing slash.
- Confirm XSOAR can reach the Cyberhaven tenant host from your network.
- If a proxy is in use, verify the proxy is configured correctly and enable the **Use system proxy settings** option in the integration configuration.

### Invalid or Expired Refresh Token (401 Unauthorized)

**Summary:**
While running Test Connectivity or executing a command, the following error appears:
`Error: Status code: 401. Unauthorized request.`

**Troubleshooting:**

- Verify the **Refresh Token** in the integration configuration is correct and has not expired.
- Generate a new Refresh Token from the Cyberhaven platform and update the integration configuration.
- Confirm the token has the necessary permissions to access the Cyberhaven API.

### No Incidents Fetched

**Summary:**
The integration is configured to fetch incidents, but no incidents appear in XSOAR.

**Troubleshooting:**

- Confirm **Fetch incidents** is enabled in the integration configuration.
- Verify the **Incident type** is set to `Cyberhaven Incident`.
- Check the **First fetch time** value. It cannot exceed 30 days; values greater than 30 days are automatically capped to 30 days.
- Check the **Status of incidents to fetch** and **Severity of incidents to fetch** filters. If the filters are too restrictive, no matching incidents may exist in Cyberhaven during the fetch window.
- Confirm the Cyberhaven tenant has DLP incidents within the configured fetch window.

### Max Fetch Limit Exceeded

**Summary:**
The **Max Fetch** parameter is set to a value greater than 200, but only 200 incidents are fetched per cycle.

**Troubleshooting:**

- The maximum allowed value for **Max Fetch** is 200. Any value greater than 200 is automatically treated as 200. Adjust your expectations or the fetch interval accordingly.

### Outgoing Mirroring Not Syncing to Cyberhaven

**Summary:**
Changes made in XSOAR (Status, Owner, Close Reason, Close Notes) are not reflected in Cyberhaven.

**Troubleshooting:**

- Confirm **Enable Outgoing Mirroring (from XSOAR to Cyberhaven)** is enabled in the integration configuration.
- Verify the Refresh Token has write permissions on the Cyberhaven platform.
- Only the following fields are mirrored from XSOAR to Cyberhaven: **Status**, **Owner**, **Close Reason**, and **Close Notes**. Changes to other fields are not synced.
- Check that the incident in XSOAR was created by this integration instance. Mirroring applies only to incidents fetched by Cyberhaven integration.

### Execution Timeout

**Summary:**
A command fails due to a timeout error.

**Troubleshooting:**

- Use the `execution-timeout` argument to extend the command timeout (value in seconds):

| `!cyberhaven-incident-list execution-timeout=120` |
| :---- |

### For Any Other Errors

- Run the failing command with the `debug-mode=true` argument to generate a detailed log file:

| `!<command_name> debug-mode=true`  Example: `!cyberhaven-incident-list debug-mode=true` |
| :---- |

- For fetch incident errors, run:

| `!<integration_instance_name>-fetch debug-mode=true`  Example: `!Cyberhaven_Instance_1-fetch debug-mode=true` |
| :---- |

- Enable integration-level debug logging from the configuration page by setting the **Log Level** to `debug`. Logs are written to `/var/log/demisto/Integration-Instance.log`.

**Reference links:**

- [https://xsoar.pan.dev/docs/reference/articles/troubleshooting-guide](https://xsoar.pan.dev/docs/reference/articles/troubleshooting-guide)
- [https://docs-cortex.paloaltonetworks.com/search/all?query=troubleshoot\&content-lang=en-US](https://docs-cortex.paloaltonetworks.com/search/all?query=troubleshoot&content-lang=en-US)
