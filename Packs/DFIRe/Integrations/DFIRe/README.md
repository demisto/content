# DFIRe

[DFIRe](https://dfire.fi/) is a self-hosted Digital Forensics and Incident Response (DFIR) case management platform built for security professionals. It provides structured case management, evidence tracking with chain of custody, IOC indicator management, and incident response workflows aligned with the NIST Incident Response framework — all running on your own infrastructure with AES-256 encryption.

This integration connects Cortex XSIAM and Cortex XSOAR to a DFIRe instance, enabling automated case creation and updates, bi-directional IOC indicator synchronization, evidence item tracking, file attachment uploads, and timeline enrichment directly from playbooks.

## Configure DFIRe in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | URL of your DFIRe instance (e.g. `https://dfire.example.com`). | True |
| API Key | Bearer API key (`dfire_ak_...`). Create under **Settings > API Keys** in DFIRe. | True |
| Trust any certificate (not secure) | Skip TLS verification for self-signed certs. | False |
| Use system proxy settings | Route requests through the configured proxy. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dfire-search

***
Searches across all DFIRe data (cases, indicators, notes, items). Supports AND, OR, NOT operators.

#### Base Command

`dfire-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search query (min 2 characters). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Search.id | String | The result ID. |
| DFIRe.Search.type | String | The result type \(e.g. case, indicator, note\). |
| DFIRe.Search.title | String | The result title. |
| DFIRe.Search.snippet | String | The matching text snippet. |
| DFIRe.Search.rank | Number | The search relevance rank. |
| DFIRe.Search.url | String | The URL to the result in DFIRe. |
| DFIRe.Search.date | Date | The result date. |

### dfire-case-type-list

***
Lists available case types and their IDs.

#### Base Command

`dfire-case-type-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseType.id | Number | The case type ID. |
| DFIRe.CaseType.name | String | The case type name. |

### dfire-case-list

***
Lists cases from DFIRe.

#### Base Command

`dfire-case-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of cases to return. Default is 50. | Optional |
| page | The page number for pagination. | Optional |
| status | The status by which to filter cases. Possible values are: OPEN, CLOSED, ARCHIVED. | Optional |
| status_in | A comma-separated list of statuses by which to filter cases, for example, "OPEN,CLOSED". | Optional |
| severity | The severity by which to filter cases. Possible values are: critical, high, medium, low, info. | Optional |
| case_mode | The mode by which to filter cases. Possible values are: investigation, incident. | Optional |
| lead_investigator | The lead investigator user ID by which to filter cases. | Optional |
| created_at_gte | The ISO-8601 datetime on or after which to filter cases, for example, "2026-05-01T00:00:00Z". | Optional |
| created_at_lte | The ISO-8601 datetime on or before which to filter cases. | Optional |
| ordering | The field by which to order results, for example, "created_at", or "-created_at" for descending order. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Case.id | Number | The case ID. |
| DFIRe.Case.title | String | The case title. |
| DFIRe.Case.case_number | String | The case number. |
| DFIRe.Case.status | String | The case status. |
| DFIRe.Case.severity | String | The case severity. |
| DFIRe.Case.case_mode | String | The case mode, investigation or incident. |
| DFIRe.Case.case_type_name | String | The case type name. |
| DFIRe.Case.lead_investigator | Number | The lead investigator user ID. |
| DFIRe.Case.created_at | Date | Case creation timestamp. |

### dfire-case-get

***
Retrieves details of a specific case.

#### Base Command

`dfire-case-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the case. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Case.id | Number | The case ID. |
| DFIRe.Case.title | String | The case title. |
| DFIRe.Case.case_number | String | The case number. |
| DFIRe.Case.description | String | The case description. |
| DFIRe.Case.notes | String | The high-level case notes. |
| DFIRe.Case.status | String | The case status. |
| DFIRe.Case.severity | String | The case severity. |
| DFIRe.Case.case_mode | String | The case mode, investigation or incident. |
| DFIRe.Case.case_type | Number | The case type ID. |
| DFIRe.Case.case_type_name | String | The case type name. |
| DFIRe.Case.external_id | String | The external reference ID. |
| DFIRe.Case.lead_investigator | Number | The lead investigator user ID. |
| DFIRe.Case.project_id | Number | The associated project ID. |
| DFIRe.Case.current_phase_name | String | The current case phase name. |
| DFIRe.Case.item_count | Number | The number of evidence items. |
| DFIRe.Case.indicator_count | Number | The number of indicators. |
| DFIRe.Case.created_at | Date | The case creation timestamp. |
| DFIRe.Case.closed_at | Date | The case closure timestamp. |

### dfire-case-create

***
Creates a new case in DFIRe.

#### Base Command

`dfire-case-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The case title. | Required |
| case_type | The case type ID. | Required |
| description | The case description. | Optional |
| notes | The high-level case summary or notes. | Optional |
| severity | The case severity. Possible values are: critical, high, medium, low, info. | Optional |
| case_mode | The case mode, investigation or incident. Possible values are: investigation, incident. | Optional |
| lead_investigator | The user ID of the lead investigator. | Optional |
| investigators | A comma-separated list of investigator user IDs. | Optional |
| viewers | A comma-separated list of viewer user IDs. | Optional |
| investigator_ids | A comma-separated list of investigator IDs (alternate write field). | Optional |
| viewer_ids | A comma-separated list of viewer IDs (alternate write field). | Optional |
| incident_category | The ENISA incident category ID. | Optional |
| outcome_verdict | The outcome verdict ID (true positive, false positive, etc.). | Optional |
| external_id | The external reference ID (e.g. ticket number). | Optional |
| project_id | The project ID to associate the case with. | Optional |
| attributes | The JSON string of custom attributes to attach to the case. | Optional |
| create_slack_channel | Whether to auto-create a Slack channel for this case. Defaults to false to avoid unintended channel creation from automated workflows. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Case.id | Number | The ID of the created case. |
| DFIRe.Case.title | String | The title of the created case. |
| DFIRe.Case.case_number | String | The assigned case number. |
| DFIRe.Case.status | String | The case status. |

### dfire-case-update

***
Updates an existing case in DFIRe.

#### Base Command

`dfire-case-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the case to update. | Required |
| title | The new title for the case. | Optional |
| description | The new case description. | Optional |
| notes | The high-level case summary or notes. | Optional |
| status | The new case status. Possible values are: OPEN, CLOSED, ARCHIVED. | Optional |
| severity | The new case severity. Possible values are: critical, high, medium, low, info. | Optional |
| case_mode | The new case mode, investigation or incident. Possible values are: investigation, incident. | Optional |
| lead_investigator | The new case lead investigator user ID. | Optional |
| investigators | A comma-separated list of user IDs with which to replace the investigator list.. | Optional |
| viewers | A comma-separated list of user IDs with which to replace the viewer list. | Optional |
| investigator_ids | A comma-separated list of investigator IDs (alternate write field). | Optional |
| viewer_ids | A comma-separated list of viewer IDs (alternate write field). | Optional |
| incident_category | The ENISA incident category ID. | Optional |
| outcome_verdict | The outcome verdict ID. | Optional |
| external_id | The new external reference ID. | Optional |
| attributes | The JSON string of custom attributes to attach to the case. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Case.id | Number | The case ID. |
| DFIRe.Case.title | String | The updated case title. |
| DFIRe.Case.status | String | The updated case status. |

### dfire-case-delete

***
Deletes a case from DFIRe.

#### Base Command

`dfire-case-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the case to delete. | Required |

#### Context Output

There is no context output for this command.

### dfire-case-note-list

***
Lists notes for a case.

#### Base Command

`dfire-case-note-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to list notes for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseNote.id | Number | The note ID. |
| DFIRe.CaseNote.case | Number | The case ID. |
| DFIRe.CaseNote.note | String | The note content. |
| DFIRe.CaseNote.author_name | String | The note author. |
| DFIRe.CaseNote.created_at | Date | The note creation timestamp. |

### dfire-case-note-create

***
Creates a note on a case.

#### Base Command

`dfire-case-note-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to add the note to. | Required |
| note | The note content. | Required |
| show_on_timeline | Whether to show this note on the case timeline. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseNote.id | Number | The created note ID. |
| DFIRe.CaseNote.case | Number | The case ID. |
| DFIRe.CaseNote.note | String | The note content. |

### dfire-indicator-list

***
Lists indicators from the global IOC registry.

#### Base Command

`dfire-indicator-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional |
| offset | The offset for pagination. Default is 0. | Optional |
| search | The search term by which to filter indicators. | Optional |
| stix_type | The STIX type by which to filter indicators. Possible values are: ipv4-addr, ipv6-addr, domain-name, url, email-addr, email-message, file, process, windows-registry-key, network-traffic, user-account, mac-addr, software, artifact, autonomous-system, directory, mutex, x509-certificate. | Optional |
| classification | The classification by which to filter indicators. Possible values are: unknown, benign, suspicious, malicious. | Optional |
| confidence | The confidence level by which to filter indicators. Possible values are: low, medium, high. | Optional |
| tlp | The TLP designation by which to filter indicators. Possible values are: clear, green, amber, amber_strict, red. | Optional |
| is_published | Whether to filter indicators by published status. Possible values are: true, false. | Optional |
| is_revoked | Whether to filter indicators by revoked status. Possible values are: true, false. | Optional |
| parent | The ID of the parent indicator by which to filter results to return its child indicators. | Optional |
| ordering | The field by which to order results, for example, "created_at", or "-confidence" for descending order. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.value | String | The IOC value. |
| DFIRe.Indicator.stix_type | String | The STIX 2.1 SCO type. |
| DFIRe.Indicator.classification | String | The indicator classification \(unknown/benign/suspicious/malicious\). |
| DFIRe.Indicator.confidence | String | The indicator confidence level. |
| DFIRe.Indicator.tlp | String | The indicator TLP designation. |
| DFIRe.Indicator.is_published | Boolean | Whether the indicator is published. |
| DFIRe.Indicator.is_revoked | Boolean | Whether the indicator is revoked. |
| DFIRe.Indicator.case_count | Number | The number of associated cases for the indicator. |
| DFIRe.Indicator.first_seen | Date | The indicator first seen timestamp. |
| DFIRe.Indicator.created_at | Date | The indicator creation timestamp. |

### dfire-indicator-get

***
Retrieves details of a specific indicator.

#### Base Command

`dfire-indicator-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The DFIRe indicator ID. |
| DFIRe.Indicator.value | String | The IOC value. |
| DFIRe.Indicator.value_normalized | String | The normalized IOC value. |
| DFIRe.Indicator.stix_type | String | The STIX 2.1 SCO type. |
| DFIRe.Indicator.classification | String | The indicator classification. |
| DFIRe.Indicator.confidence | String | The indicator confidence level. |
| DFIRe.Indicator.tlp | String | The indicator TLP designation. |
| DFIRe.Indicator.tags | Unknown | The tags assigned to the indicator. |
| DFIRe.Indicator.public_notes | String | The indicator public notes. |
| DFIRe.Indicator.is_published | Boolean | Whether the indicator is published. |
| DFIRe.Indicator.is_revoked | Boolean | Whether the indicator is revoked. |
| DFIRe.Indicator.parent | Number | The parent indicator ID. |
| DFIRe.Indicator.case_count | Number | The number of associated cases for the indicator. |
| DFIRe.Indicator.children_count | Number | The number of child indicators. |
| DFIRe.Indicator.first_seen | Date | The indicator first seen timestamp. |
| DFIRe.Indicator.last_seen | Date | The indicator last seen timestamp. |
| DFIRe.Indicator.created_at | Date | The indicator creation timestamp. |

### dfire-indicator-create

***
Creates a new indicator in the global IOC registry.

#### Base Command

`dfire-indicator-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The IOC value (IP, domain, hash, URL, etc.). | Required |
| stix_type | The STIX 2.1 SCO type. Possible values are: ipv4-addr, ipv6-addr, domain-name, url, email-addr, email-message, file, process, windows-registry-key, network-traffic, user-account, mac-addr, software, artifact, autonomous-system, directory, mutex, x509-certificate. | Required |
| classification | The indicator classification. Possible values are: unknown, benign, suspicious, malicious. | Optional |
| confidence | The indicator confidence level. Possible values are: low, medium, high. | Optional |
| tlp | The incidator TLP designation. Possible values are: clear, green, amber, amber_strict, red. | Optional |
| tags | A comma-separated list of indicator tags. | Optional |
| public_notes | The public notes about the indicator. | Optional |
| valid_until | The indicator auto-revoke date (ISO 8601). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The created indicator ID. |
| DFIRe.Indicator.value | String | The indicator value. |
| DFIRe.Indicator.stix_type | String | The indicator STIX type. |
| DFIRe.Indicator.is_existing | Boolean | Whether the indicator already exists. |

### dfire-indicator-update

***
Updates an existing indicator.

#### Base Command

`dfire-indicator-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID to update. | Required |
| classification | The new indicator classification. Possible values are: unknown, benign, suspicious, malicious. | Optional |
| confidence | The new indicator confidence level. Possible values are: low, medium, high. | Optional |
| tlp | The new indicator TLP designation. Possible values are: clear, green, amber, amber_strict, red. | Optional |
| tags | A comma-separated list of new indicator tags (replaces the existing). | Optional |
| public_notes | The new indicator public notes. | Optional |
| valid_until | The new indicator auto-revoke date (ISO 8601). Set it to empty to clear. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.value | String | The IOC value. |
| DFIRe.Indicator.classification | String | The updated indicator classification. |

### dfire-indicator-delete

***
Deletes an indicator from the global IOC registry.

#### Base Command

`dfire-indicator-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID to delete. | Required |

#### Context Output

There is no context output for this command.

### dfire-item-type-list

***
Lists available evidence item types and their IDs.

#### Base Command

`dfire-item-type-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.ItemType.id | Number | The item type ID. |
| DFIRe.ItemType.name | String | The item type name. |
| DFIRe.ItemType.icon | String | The item type icon. |

### dfire-item-flag-list

***
Lists available item flags and their IDs.

#### Base Command

`dfire-item-flag-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.ItemFlag.id | Number | The flag ID. |
| DFIRe.ItemFlag.name | String | The flag name. |
| DFIRe.ItemFlag.color | String | The flag color. |
| DFIRe.ItemFlag.description | String | The flag description. |

### dfire-item-list

***
Lists evidence items, optionally filtered by case.

#### Base Command

`dfire-item-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID by which to filter evidence items. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Item.uuid | String | The evidence item UUID. |
| DFIRe.Item.name | String | The evidence item name. |
| DFIRe.Item.display_title | String | The evidence item display title. |
| DFIRe.Item.item_type_name | String | The evidence item type name. |
| DFIRe.Item.case | Number | The evidence item associated case ID. |
| DFIRe.Item.location | String | The evidence item location. |
| DFIRe.Item.attachment_count | Number | The number of attachments to the evidence item. |
| DFIRe.Item.created_at | Date | The evidence item creation timestamp. |

### dfire-item-get

***
Retrieves details of a specific evidence item.

#### Base Command

`dfire-item-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The evidence item ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Item.uuid | String | The evidence item UUID. |
| DFIRe.Item.name | String | The evidence item name. |
| DFIRe.Item.display_title | String | The evidence item display title. |
| DFIRe.Item.item_type_name | String | The evidence item type name. |
| DFIRe.Item.case | Number | The evidence item associated case ID. |
| DFIRe.Item.location | String | The evidence item location. |
| DFIRe.Item.attachment_count | Number | The number of attachments for the evidence item. |
| DFIRe.Item.created_at | Date | The evidence item creation timestamp. |

### dfire-item-create

***
Creates a new evidence item on a case.

#### Base Command

`dfire-item-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to add the evidence item to. | Required |
| item_type | The evidence item type ID. | Required |
| location | The evidence item location (e.g. storage location, lab). | Required |
| name | The friendly name/label for the evidence item. | Optional |
| owner_id | The legal entity ID of the evidence item owner. | Optional |
| primary_user_id | The legal entity ID of the primary user. | Optional |
| collected_by | The user ID of the collector. | Optional |
| parent_item | The UUID of the parent evidence item. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Item.uuid | String | The created evidence item UUID. |
| DFIRe.Item.name | String | The evidence item name. |
| DFIRe.Item.case | Number | The case ID. |

### dfire-attachment-list

***
Lists attachments, optionally filtered by evidence item UUID.

#### Base Command

`dfire-attachment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_uuid | The evidence item UUID by which to filter attachments. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Attachment.id | Number | The attachment ID. |
| DFIRe.Attachment.filename | String | The attachment filename. |
| DFIRe.Attachment.mime_type | String | The attachment MIME type. |
| DFIRe.Attachment.size | Number | The attachment file size in bytes. |
| DFIRe.Attachment.category | String | The attachment category. |
| DFIRe.Attachment.case | Number | The attachment associated case ID. |
| DFIRe.Attachment.item | String | The attachment associated evidence item UUID. |
| DFIRe.Attachment.hash_sha256 | String | The SHA-256 hash of the plaintext file attachment. |
| DFIRe.Attachment.uploaded_by_name | String | Who uploaded the file attachment. |
| DFIRe.Attachment.uploaded_at | Date | The attachment upload timestamp. |

### dfire-attachment-get

***
Gets details of a specific attachment.

#### Base Command

`dfire-attachment-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachment_id | The attachment ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Attachment.id | Number | The DFIRe attachment ID. |
| DFIRe.Attachment.filename | String | The attachment filename. |
| DFIRe.Attachment.mime_type | String | The attachment MIME type. |
| DFIRe.Attachment.size | Number | The attachment file size in bytes. |
| DFIRe.Attachment.category | String | The attachment category. |
| DFIRe.Attachment.description | String | The attachment user-provided description. |
| DFIRe.Attachment.hash_sha256 | String | The SHA-256 hash of the plaintext file attachment. |
| DFIRe.Attachment.status | String | The attachment upload/encryption status. |
| DFIRe.Attachment.storage_location | String | The attachment storage location \(local, s3, smb\). |
| DFIRe.Attachment.uploaded_at | Date | The attachment upload timestamp. |

### dfire-attachment-upload

***
Uploads a file as an attachment to a case or evidence item.

#### Base Command

`dfire-attachment-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the file to upload. | Required |
| case_id | The case ID to associate the attachment with. | Optional |
| item_uuid | The evidence item UUID to associate the attachment with. | Optional |
| filename | The name with which to override the filename. (default is the uploaded file name). | Optional |
| category | The attachment category. `general` routes to the encrypted file store and is relevant for most playbooks. `evidence` is reserved for evidence photos and routes to the image gallery, not the file store. Possible values are: general, evidence. Default is general. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Attachment.id | Number | The created attachment ID. |
| DFIRe.Attachment.filename | String | The attachment filename. |
| DFIRe.Attachment.size | Number | The attachment file size in bytes. |

### dfire-attachment-delete

***
Deletes an attachment.

#### Base Command

`dfire-attachment-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachment_id | The attachment ID to delete. | Required |

#### Context Output

There is no context output for this command.

### dfire-timeline-list

***
Lists timeline events for a case (newest first).

#### Base Command

`dfire-timeline-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.TimelineEvent.id | Number | The timeline event ID. |
| DFIRe.TimelineEvent.event_type | String | The timeline event type. |
| DFIRe.TimelineEvent.subject | String | The timeline event subject. |
| DFIRe.TimelineEvent.details | String | The timeline event details. |
| DFIRe.TimelineEvent.event_datetime | Date | When the timeline event occurred. |
| DFIRe.TimelineEvent.created_by_name | String | Who created the timeline event. |

### dfire-timeline-create

***
Adds a manual timeline event to a case.

#### Base Command

`dfire-timeline-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| subject | The timeline event subject line. | Required |
| details | The timeline event description. | Optional |
| event_datetime | When the timeline event occurred (ISO 8601). Default is now. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.TimelineEvent.id | Number | The created timeline event ID. |
| DFIRe.TimelineEvent.subject | String | The timeline event subject. |
| DFIRe.TimelineEvent.event_datetime | Date | The timeline event timestamp. |

### dfire-user-list

***
Lists users in the DFIRe tenant. Useful for looking up user IDs for assignments.

#### Base Command

`dfire-user-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.User.id | Number | The DFIRe user ID. |
| DFIRe.User.username | String | The DFIRe username. |
| DFIRe.User.full_name | String | The DFIRe user's full name. |
| DFIRe.User.email | String | The DFIRe user's email. |
| DFIRe.User.is_active | Boolean | Whether the DFIRe user is active. |
| DFIRe.User.groups | Unknown | Groups the DFIRe user belongs to. |

### dfire-case-indicator-list

***
Lists indicators associated with a case.

#### Base Command

`dfire-case-indicator-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseIndicator.id | Number | The association ID. |
| DFIRe.CaseIndicator.case | Number | The case ID. |
| DFIRe.CaseIndicator.indicator.id | Number | The indicator ID. |
| DFIRe.CaseIndicator.indicator.value | String | The indicator value. |
| DFIRe.CaseIndicator.indicator.stix_type | String | The indicator STIX type. |
| DFIRe.CaseIndicator.context | String | The case private notes about the associated indicator. |
| DFIRe.CaseIndicator.source | String | How the associated indicator was added. |
| DFIRe.CaseIndicator.created_at | Date | The association timestamp. |
| DFIRe.CaseIndicator.case_count | Number | The number of cases this indicator appears in. |

### dfire-case-indicator-add

***
Adds an indicator to a case. Creates the indicator if it does not exist.

#### Base Command

`dfire-case-indicator-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| value | The indicator value. | Required |
| stix_type | The indicator STIX 2.1 SCO type. Possible values are: ipv4-addr, ipv6-addr, domain-name, url, email-addr, email-message, file, process, windows-registry-key, network-traffic, user-account, mac-addr, software, artifact, autonomous-system, directory, mutex, x509-certificate. | Required |
| classification | The indicator classification. Possible values are: unknown, benign, suspicious, malicious. Default is unknown. | Optional |
| confidence | The indicator confidence level. Possible values are: low, medium, high. Default is low. | Optional |
| tlp | The indicator TLP designation. Possible values are: clear, green, amber, amber_strict, red. Default is amber. | Optional |
| context | The case private notes about the indicator. | Optional |
| tags | A comma-separated list of indicator tags. | Optional |
| source | The source from which the indicator was obtained. Possible values are: manual, automated, threat_intel, sandbox, enrichment, import. | Optional |
| source_reference | The free-form reference identifying the source (URL, ticket, report name, etc.). | Optional |
| valid_until | The ISO-8601 datetime after which to automatically invalidate the indicator, for example, "2026-12-31T00:00:00Z". | Optional |
| decompose | Whether to auto-decompose the indicator (URL→domain, email→domain). Possible values are: true, false. Default is true. | Optional |
| publish | Whether to publish the indicator immediately after creation. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseIndicator.id | Number | The association ID. |
| DFIRe.CaseIndicator.indicator.id | Number | The indicator ID. |
| DFIRe.CaseIndicator.indicator.value | String | The indicator value. |

### dfire-case-indicator-remove

***
Removes an indicator association from a case.

#### Base Command

`dfire-case-indicator-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| association_id | The case indicator association ID. | Required |

#### Context Output

There is no context output for this command.

### dfire-ioc-extract

***
Extracts candidate IOCs from a block of text. Returns suggestions only — does not add them to any case.

#### Base Command

`dfire-ioc-extract`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | The text to scan to extract indicators from. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IOCExtraction.candidates | Unknown | The list of extracted indicator candidates. |

### dfire-indicator-check

***
Batch-checks whether IOCs already exist in the global registry.

#### Base Command

`dfire-indicator-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | The JSON array of {value, stix_type} objects (mutually exclusive with values+stix_type). | Optional |
| values | A comma-separated indicator values to check (used with stix_type). | Optional |
| stix_type | The STIX type to use when checking the values argument. Possible values are: ipv4-addr, ipv6-addr, domain-name, url, email-addr, email-message, file, process, windows-registry-key, network-traffic, user-account, mac-addr, software, artifact, autonomous-system, directory, mutex, x509-certificate. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IndicatorCheck.results | Unknown | The status and details of each submitted indicator. |

### dfire-indicator-enrich

***
Triggers external enrichment for an indicator.

#### Base Command

`dfire-indicator-enrich`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |
| providers | A comma-separated list of provider names (omit this to run all providers). | Optional |
| force | Whether to re-enrich even if cached results exist. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |

### dfire-indicator-enrichment-list

***
Retrieves cached enrichment results for an indicator.

#### Base Command

`dfire-indicator-enrichment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Enrichment.enrichments | Unknown | The enrichment records. |

### dfire-indicator-publish

***
Publishes an indicator (making it visible to TAXII consumers and STIX exports).

#### Base Command

`dfire-indicator-publish`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The DFIRe indicator ID. |
| DFIRe.Indicator.is_published | Boolean | Whether the indicator is published. |

### dfire-indicator-unpublish

***
Unpublishes an indicator.

#### Base Command

`dfire-indicator-unpublish`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The DFIRe indicator ID. |
| DFIRe.Indicator.is_published | Boolean | Whether the indicator is published. |

### dfire-indicator-revoke

***
Revokes an indicator.

#### Base Command

`dfire-indicator-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The DFIRe indicator ID. |
| DFIRe.Indicator.is_revoked | Boolean | Whether the indicator is revoked. |

### dfire-indicator-unrevoke

***
Unrevokes an indicator.

#### Base Command

`dfire-indicator-unrevoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The DFIRe indicator ID. |
| DFIRe.Indicator.is_revoked | Boolean | Whether the indicator is revoked. |

### dfire-indicator-decompose

***
Auto-decomposes an indicator (URL→domain, email→domain, etc.).

#### Base Command

`dfire-indicator-decompose`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The DFIRe indicator ID. |

### dfire-indicator-add-tags

***
Merges a list of tags into the indicator's existing tag set.

#### Base Command

`dfire-indicator-add-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |
| tags | A comma-separated list of tags to add. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The DFIRe indicator ID. |
| DFIRe.Indicator.tags | Unknown | The updated tag list. |

### dfire-indicator-correlated-list

***
Lists indicators that appear in multiple cases.

#### Base Command

`dfire-indicator-correlated-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IndicatorCorrelated.results | Unknown | The indicators correlated across cases. |

### dfire-indicator-bulk-classify

***
Bulk-updates classification for multiple indicators.

#### Base Command

`dfire-indicator-bulk-classify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | A comma-separated list of indicator IDs. | Required |
| classification | The new indicator classification. Possible values are: unknown, benign, suspicious, malicious. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | The bulk operation result. |

### dfire-indicator-bulk-confidence

***
The bulk-update confidence for multiple indicators.

#### Base Command

`dfire-indicator-bulk-confidence`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | A comma-separated list of indicator IDs. | Required |
| confidence | The new indicator confidence level. Possible values are: low, medium, high. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | The bulk operation result. |

### dfire-indicator-bulk-tag

***
Bulk adds/removes/sets tags on multiple indicators.

#### Base Command

`dfire-indicator-bulk-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | A comma-separated list of indicator IDs. | Required |
| tags | A comma-separated list of indicator tags. | Required |
| mode | The action to perform on the tags (add, remove, set). Possible values are: add, remove, set. Default is add. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | The bulk operation result. |

### dfire-indicator-bulk-tlp

***
Bulk-updates TLP designation for multiple indicators.

#### Base Command

`dfire-indicator-bulk-tlp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | A comma-separated list of indicator IDs. | Required |
| tlp | The new indicator TLP designation. Possible values are: clear, green, amber, amber_strict, red. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | The bulk operation result. |

### dfire-indicator-bulk-publish

***
Bulk-publishes indicators.

#### Base Command

`dfire-indicator-bulk-publish`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | A comma-separated list of indicator IDs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkPublishResponse.published_count | Number | The number of indicators published. |
| DFIRe.BulkPublishResponse.skipped_revoked | Number | The number of indicators skipped because they were revoked. |
| DFIRe.BulkPublishResponse.skipped_red | Number | The number of indicators skipped because of TLP status RED. |

### dfire-indicator-bulk-revoke

***
Bulk-revokes indicators.

#### Base Command

`dfire-indicator-bulk-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | A comma-separated list of indicator IDs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | The bulk operation result. |

### dfire-indicator-bulk-delete

***
Bulk-deletes indicators.

#### Base Command

`dfire-indicator-bulk-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | A comma-separated list of indicator IDs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | The bulk operation result. |

### dfire-case-generate-summary

***
Triggers an AI-generated executive summary for a case.

#### Base Command

`dfire-case-generate-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseSummary | Unknown | The summary result. |

### dfire-case-chat

***
Sends a chat message to the case AI assistant.

#### Base Command

`dfire-case-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| message | The user message to send. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseChat | Unknown | The chat response. |

### dfire-case-update-report

***
Updates the text of an AI-generated report attached to a case (e.g. an executive summary).

#### Base Command

`dfire-case-update-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID the report belongs to. | Required |
| report_id | The ID of the generated report to update. | Required |
| report_text | The new report text content. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseReport | Unknown | The updated report. |

### dfire-case-can-report-list

***
Lists CAN (Case Activity Notice) reports for a case.

#### Base Command

`dfire-case-can-report-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CANReport.id | Number | The CAN report ID. |

### dfire-case-can-report-generate

***
Generates a new CAN report for a case.

#### Base Command

`dfire-case-can-report-generate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| body | The optional JSON body describing the report parameters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CANReport.id | Number | The generated report ID. |

### dfire-case-investigation-report-get

***
Retrieves the investigation report for a case.

#### Base Command

`dfire-case-investigation-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.InvestigationReport | Unknown | The investigation report. |

### dfire-case-investigation-report-generate

***
Generates AI content for a single section of a case's investigation report. Returns preview content; does not auto-save.

#### Base Command

`dfire-case-investigation-report-generate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| section_id | The ID of the report section to generate content for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.InvestigationReport.content | String | The generated section content. |
| DFIRe.InvestigationReport.model | String | The model used to generate the content. |

### dfire-case-investigation-report-finalize

***
Finalizes the investigation report for a case.

#### Base Command

`dfire-case-investigation-report-finalize`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.InvestigationReport | Unknown | The finalized investigation report. |

### dfire-case-investigation-report-ready-for-qa

***
Marks a single section of the investigation report as ready for QA review.

#### Base Command

`dfire-case-investigation-report-ready-for-qa`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| section_id | The ID of the report section to mark ready for QA. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.InvestigationReport | Unknown | The investigation report section after the state change. |

### dfire-case-timeline-change-phase

***
Moves a case to a new response phase in the timeline.

#### Base Command

`dfire-case-timeline-change-phase`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| phase_id | The target phase ID. | Optional |
| phase_name | The target phase name (used if phase_id is omitted). | Optional |
| note | The optional note explaining the phase change. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.TimelineEvent.id | Number | The created phase change timeline event ID. |

### dfire-case-todo-list

***
Lists todos for a case.

#### Base Command

`dfire-case-todo-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | The todo ID. |
| DFIRe.CaseTodo.title | String | The todo title. |
| DFIRe.CaseTodo.status | String | The todo status. |

### dfire-case-todo-get

***
Retrieves a single todo with full details.

#### Base Command

`dfire-case-todo-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| todo_id | The todo ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | The todo ID. |

### dfire-case-todo-assign

***
Assigns a todo to a user.

#### Base Command

`dfire-case-todo-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| todo_id | The todo ID. | Required |
| user_id | The user ID of the assignee. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | The todo ID. |
| DFIRe.CaseTodo.assignee_name | String | The assignee display name. |

### dfire-case-todo-note-set

***
Sets or replaces the note on a todo.

#### Base Command

`dfire-case-todo-note-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| todo_id | The todo ID. | Required |
| note | The new note content. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | The todo ID. |

### dfire-case-todo-attach-runbook

***
Attaches a runbook to a todo.

#### Base Command

`dfire-case-todo-attach-runbook`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| todo_id | The todo ID. | Required |
| runbook_slug | The runbook slug to attach. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | The todo ID. |
| DFIRe.CaseTodo.runbook_slug | String | The attached runbook slug. |

### dfire-case-todo-detach-runbook

***
Detaches the runbook from a todo.

#### Base Command

`dfire-case-todo-detach-runbook`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| todo_id | The todo ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | The todo ID. |

### dfire-case-timer-list

***
Lists the SLA timers for a case.

#### Base Command

`dfire-case-timer-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTimer.id | Number | The timer ID. |
| DFIRe.CaseTimer.name | String | The timer name. |
| DFIRe.CaseTimer.framework | String | The compliance framework. |

### dfire-case-timer-get

***
Retrieves a single SLA timer.

#### Base Command

`dfire-case-timer-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| timer_id | The timer ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTimer.id | Number | The timer ID. |

### dfire-case-timer-complete

***
Marks a case SLA timer as complete.

#### Base Command

`dfire-case-timer-complete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| timer_id | The timer ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTimer.id | Number | The timer ID. |

### dfire-case-timer-reset

***
Resets a case SLA timer.

#### Base Command

`dfire-case-timer-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| timer_id | The timer ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTimer.id | Number | The timer ID. |

### dfire-case-get-by-number

***
Looks up a case by its human-readable case number.

#### Base Command

`dfire-case-get-by-number`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_number | The case number (e.g. "CASE-2026-0001"). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Case.id | Number | The case ID. |
| DFIRe.Case.case_number | String | The case number. |

### dfire-item-resolve-short-id

***
Resolves an 8-character item short ID to its full UUID and parent case ID.

#### Base Command

`dfire-item-resolve-short-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| short_id | The first 8 characters of the item UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Item.uuid | String | The full item UUID. |
| DFIRe.Item.case | Number | The parent case ID. |

### dfire-incident-category-list

***
Lists ENISA incident categories (useful for picklists).

#### Base Command

`dfire-incident-category-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IncidentCategory.id | Number | The category ID. |
| DFIRe.IncidentCategory.name | String | The category name. |

### dfire-incident-phase-list

***
Lists configured incident-response phases.

#### Base Command

`dfire-incident-phase-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IncidentPhase.id | Number | The phase ID. |
| DFIRe.IncidentPhase.name | String | The phase name. |

### dfire-outcome-verdict-list

***
Lists case outcome verdicts (true positive, false positive, etc.).

#### Base Command

`dfire-outcome-verdict-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.OutcomeVerdict.id | Number | The verdict ID. |
| DFIRe.OutcomeVerdict.name | String | The verdict name. |

### dfire-project-list

***
Lists projects.

#### Base Command

`dfire-project-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Project.id | Number | The project ID. |
| DFIRe.Project.name | String | The project name. |

### dfire-runbook-list

***
Lists available runbooks (used for todo runbook attachments).

#### Base Command

`dfire-runbook-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Runbook.slug | String | The runbook slug. |
| DFIRe.Runbook.name | String | The runbook name. |

### dfire-group-list

***
Lists user groups.

#### Base Command

`dfire-group-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Group.id | Number | The user group ID. |
| DFIRe.Group.name | String | The user group name. |
