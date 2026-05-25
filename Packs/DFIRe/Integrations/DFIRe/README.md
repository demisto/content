# DFIRe

[DFIRe](https://dfire.fi/) is a self-hosted Digital Forensics and Incident Response (DFIR) case management platform built for security professionals. It provides structured case management, evidence tracking with chain of custody, IOC indicator management, and incident response workflows aligned with the NIST Incident Response framework — all running on your own infrastructure with AES-256 encryption.

This integration connects Cortex XSIAM to a DFIRe instance, enabling automated case creation and updates, bi-directional IOC indicator synchronisation, evidence item tracking, file attachment uploads, and timeline enrichment directly from playbooks.

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
Search across all DFIRe data (cases, indicators, notes, items). Supports AND, OR, NOT operators.

#### Base Command

`dfire-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search query (min 2 characters). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Search.id | String | The result ID. |
| DFIRe.Search.type | String | The result type \(e.g. case, indicator, note\). |
| DFIRe.Search.title | String | The result title. |
| DFIRe.Search.snippet | String | Matching text snippet. |
| DFIRe.Search.rank | Number | Search relevance rank. |
| DFIRe.Search.url | String | URL to the result in DFIRe. |
| DFIRe.Search.date | Date | Result date. |

### dfire-case-type-list

***
List available case types and their IDs.

#### Base Command

`dfire-case-type-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseType.id | Number | The case type ID. |
| DFIRe.CaseType.name | String | The case type name. |

### dfire-case-list

***
List cases from DFIRe.

#### Base Command

`dfire-case-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of cases to return. Default is 50. | Optional |
| page | Page number for pagination. | Optional |
| status | Filter by case status. Possible values are: OPEN, CLOSED, ARCHIVED. | Optional |
| status_in | Filter by multiple statuses (comma-separated, e.g. "OPEN,CLOSED"). | Optional |
| severity | Filter by severity. Possible values are: critical, high, medium, low, info. | Optional |
| case_mode | Filter by case mode. Possible values are: investigation, incident. | Optional |
| lead_investigator | Filter by lead investigator user ID. | Optional |
| created_at_gte | Filter cases created on or after this ISO-8601 datetime (e.g. "2026-05-01T00:00:00Z"). | Optional |
| created_at_lte | Filter cases created on or before this ISO-8601 datetime. | Optional |
| ordering | Order results by field (e.g. "created_at", "-created_at" for descending). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Case.id | Number | The case ID. |
| DFIRe.Case.title | String | The case title. |
| DFIRe.Case.case_number | String | The case number. |
| DFIRe.Case.status | String | The case status. |
| DFIRe.Case.severity | String | The case severity. |
| DFIRe.Case.case_mode | String | Investigation or incident. |
| DFIRe.Case.case_type_name | String | The case type name. |
| DFIRe.Case.lead_investigator | Number | Lead investigator user ID. |
| DFIRe.Case.created_at | Date | Case creation timestamp. |

### dfire-case-get

***
Get details of a specific case.

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
| DFIRe.Case.notes | String | High-level case notes. |
| DFIRe.Case.status | String | The case status. |
| DFIRe.Case.severity | String | The case severity. |
| DFIRe.Case.case_mode | String | Investigation or incident. |
| DFIRe.Case.case_type | Number | The case type ID. |
| DFIRe.Case.case_type_name | String | The case type name. |
| DFIRe.Case.external_id | String | External reference ID. |
| DFIRe.Case.lead_investigator | Number | Lead investigator user ID. |
| DFIRe.Case.project_id | Number | Associated project ID. |
| DFIRe.Case.current_phase_name | String | Current incident phase name. |
| DFIRe.Case.item_count | Number | Number of evidence items. |
| DFIRe.Case.indicator_count | Number | Number of indicators. |
| DFIRe.Case.created_at | Date | Case creation timestamp. |
| DFIRe.Case.closed_at | Date | Case closure timestamp. |

### dfire-case-create

***
Create a new case in DFIRe.

#### Base Command

`dfire-case-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The case title. | Required |
| case_type | The case type ID. | Required |
| description | The case description. | Optional |
| notes | High-level case summary or notes. | Optional |
| severity | The case severity. Possible values are: critical, high, medium, low, info. | Optional |
| case_mode | Investigation or incident mode. Possible values are: investigation, incident. | Optional |
| lead_investigator | User ID of the lead investigator. | Optional |
| investigators | Comma-separated list of investigator user IDs. | Optional |
| viewers | Comma-separated list of viewer user IDs. | Optional |
| investigator_ids | Comma-separated list of investigator IDs (alternate write field). | Optional |
| viewer_ids | Comma-separated list of viewer IDs (alternate write field). | Optional |
| incident_category | ENISA incident category ID. | Optional |
| outcome_verdict | Outcome verdict ID (true positive, false positive, etc.). | Optional |
| external_id | External reference ID (e.g. ticket number). | Optional |
| project_id | Project ID to associate the case with. | Optional |
| attributes | JSON string of custom attributes to attach to the case. | Optional |
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
Update an existing case in DFIRe.

#### Base Command

`dfire-case-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the case to update. | Required |
| title | New title for the case. | Optional |
| description | New description. | Optional |
| notes | High-level case summary or notes. | Optional |
| status | New status. Possible values are: OPEN, CLOSED, ARCHIVED. | Optional |
| severity | New severity. Possible values are: critical, high, medium, low, info. | Optional |
| case_mode | New case mode. Possible values are: investigation, incident. | Optional |
| lead_investigator | New lead investigator user ID. | Optional |
| investigators | Replace investigator list (comma-separated user IDs). | Optional |
| viewers | Replace viewer list (comma-separated user IDs). | Optional |
| investigator_ids | Comma-separated list of investigator IDs (alternate write field). | Optional |
| viewer_ids | Comma-separated list of viewer IDs (alternate write field). | Optional |
| incident_category | ENISA incident category ID. | Optional |
| outcome_verdict | Outcome verdict ID. | Optional |
| external_id | New external reference ID. | Optional |
| attributes | JSON string of custom attributes to attach to the case. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Case.id | Number | The case ID. |
| DFIRe.Case.title | String | The updated case title. |
| DFIRe.Case.status | String | The updated case status. |

### dfire-case-delete

***
Delete a case from DFIRe.

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
List notes for a case.

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
| DFIRe.CaseNote.created_at | Date | Note creation timestamp. |

### dfire-case-note-create

***
Create a note on a case.

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
List indicators from the global IOC registry.

#### Base Command

`dfire-indicator-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of indicators to return. Default is 50. | Optional |
| offset | Offset for pagination. Default is 0. | Optional |
| search | Search term to filter indicators. | Optional |
| stix_type | Filter by STIX type. Possible values are: ipv4-addr, ipv6-addr, domain-name, url, email-addr, email-message, file, process, windows-registry-key, network-traffic, user-account, mac-addr, software, artifact, autonomous-system, directory, mutex, x509-certificate. | Optional |
| classification | Filter by classification. Possible values are: unknown, benign, suspicious, malicious. | Optional |
| confidence | Filter by confidence level. Possible values are: low, medium, high. | Optional |
| tlp | Filter by TLP designation. Possible values are: clear, green, amber, amber_strict, red. | Optional |
| is_published | Filter by published status. Possible values are: true, false. | Optional |
| is_revoked | Filter by revoked status. Possible values are: true, false. | Optional |
| parent | Filter by parent indicator ID (returns children of this indicator). | Optional |
| ordering | Order results by field (e.g. "created_at", "-confidence"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.value | String | The IOC value. |
| DFIRe.Indicator.stix_type | String | STIX 2.1 SCO type. |
| DFIRe.Indicator.classification | String | Classification \(unknown/benign/suspicious/malicious\). |
| DFIRe.Indicator.confidence | String | Confidence level. |
| DFIRe.Indicator.tlp | String | TLP designation. |
| DFIRe.Indicator.is_published | Boolean | Whether the indicator is published. |
| DFIRe.Indicator.is_revoked | Boolean | Whether the indicator is revoked. |
| DFIRe.Indicator.case_count | Number | Number of associated cases. |
| DFIRe.Indicator.first_seen | Date | First seen timestamp. |
| DFIRe.Indicator.created_at | Date | Creation timestamp. |

### dfire-indicator-get

***
Get details of a specific indicator.

#### Base Command

`dfire-indicator-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.value | String | The IOC value. |
| DFIRe.Indicator.value_normalized | String | Normalized IOC value. |
| DFIRe.Indicator.stix_type | String | STIX 2.1 SCO type. |
| DFIRe.Indicator.classification | String | Classification. |
| DFIRe.Indicator.confidence | String | Confidence level. |
| DFIRe.Indicator.tlp | String | TLP designation. |
| DFIRe.Indicator.tags | Unknown | Tags assigned to the indicator. |
| DFIRe.Indicator.public_notes | String | Public notes. |
| DFIRe.Indicator.is_published | Boolean | Whether published. |
| DFIRe.Indicator.is_revoked | Boolean | Whether revoked. |
| DFIRe.Indicator.parent | Number | Parent indicator ID. |
| DFIRe.Indicator.case_count | Number | Number of associated cases. |
| DFIRe.Indicator.children_count | Number | Number of child indicators. |
| DFIRe.Indicator.first_seen | Date | First seen timestamp. |
| DFIRe.Indicator.last_seen | Date | Last seen timestamp. |
| DFIRe.Indicator.created_at | Date | Creation timestamp. |

### dfire-indicator-create

***
Create a new indicator in the global IOC registry.

#### Base Command

`dfire-indicator-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The IOC value (IP, domain, hash, URL, etc.). | Required |
| stix_type | STIX 2.1 SCO type. Possible values are: ipv4-addr, ipv6-addr, domain-name, url, email-addr, email-message, file, process, windows-registry-key, network-traffic, user-account, mac-addr, software, artifact, autonomous-system, directory, mutex, x509-certificate. | Required |
| classification | IOC classification. Possible values are: unknown, benign, suspicious, malicious. | Optional |
| confidence | Confidence level. Possible values are: low, medium, high. | Optional |
| tlp | TLP designation. Possible values are: clear, green, amber, amber_strict, red. | Optional |
| tags | Comma-separated tags. | Optional |
| public_notes | Public notes about the indicator. | Optional |
| valid_until | Auto-revoke date (ISO 8601). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The created indicator ID. |
| DFIRe.Indicator.value | String | The IOC value. |
| DFIRe.Indicator.stix_type | String | STIX type. |
| DFIRe.Indicator.is_existing | Boolean | Whether the indicator already existed. |

### dfire-indicator-update

***
Update an existing indicator.

#### Base Command

`dfire-indicator-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID to update. | Required |
| classification | New classification. Possible values are: unknown, benign, suspicious, malicious. | Optional |
| confidence | New confidence level. Possible values are: low, medium, high. | Optional |
| tlp | New TLP designation. Possible values are: clear, green, amber, amber_strict, red. | Optional |
| tags | New comma-separated tags (replaces existing). | Optional |
| public_notes | New public notes. | Optional |
| valid_until | New auto-revoke date (ISO 8601). Set empty to clear. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.value | String | The IOC value. |
| DFIRe.Indicator.classification | String | Updated classification. |

### dfire-indicator-delete

***
Delete an indicator from the global IOC registry.

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
List available evidence item types and their IDs.

#### Base Command

`dfire-item-type-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.ItemType.id | Number | The item type ID. |
| DFIRe.ItemType.name | String | The item type name. |
| DFIRe.ItemType.icon | String | The item type icon. |

### dfire-item-flag-list

***
List available item flags and their IDs.

#### Base Command

`dfire-item-flag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.ItemFlag.id | Number | The flag ID. |
| DFIRe.ItemFlag.name | String | The flag name. |
| DFIRe.ItemFlag.color | String | The flag color. |
| DFIRe.ItemFlag.description | String | The flag description. |

### dfire-item-list

***
List evidence items, optionally filtered by case.

#### Base Command

`dfire-item-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Filter items by case ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Item.uuid | String | The item UUID. |
| DFIRe.Item.name | String | The item name. |
| DFIRe.Item.display_title | String | The item display title. |
| DFIRe.Item.item_type_name | String | The item type name. |
| DFIRe.Item.case | Number | The associated case ID. |
| DFIRe.Item.location | String | The item location. |
| DFIRe.Item.attachment_count | Number | Number of attachments. |
| DFIRe.Item.created_at | Date | Creation timestamp. |

### dfire-item-get

***
Get details of a specific evidence item.

#### Base Command

`dfire-item-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The item ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Item.uuid | String | The item UUID. |
| DFIRe.Item.name | String | The item name. |
| DFIRe.Item.display_title | String | The item display title. |
| DFIRe.Item.item_type_name | String | The item type name. |
| DFIRe.Item.case | Number | The associated case ID. |
| DFIRe.Item.location | String | The item location. |
| DFIRe.Item.attachment_count | Number | Number of attachments. |
| DFIRe.Item.created_at | Date | Creation timestamp. |

### dfire-item-create

***
Create a new evidence item on a case.

#### Base Command

`dfire-item-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to add the item to. | Required |
| item_type | The item type ID. | Required |
| location | The item location (e.g. storage location, lab). | Required |
| name | Friendly name/label for the item. | Optional |
| owner_id | Legal entity ID of the item owner. | Optional |
| primary_user_id | Legal entity ID of the primary user. | Optional |
| collected_by | User ID of the collector. | Optional |
| parent_item | UUID of the parent item. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Item.uuid | String | The created item UUID. |
| DFIRe.Item.name | String | The item name. |
| DFIRe.Item.case | Number | The case ID. |

### dfire-attachment-list

***
List attachments, optionally filtered by evidence item UUID.

#### Base Command

`dfire-attachment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_uuid | Filter attachments by evidence item UUID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Attachment.id | Number | The attachment ID. |
| DFIRe.Attachment.filename | String | The filename. |
| DFIRe.Attachment.mime_type | String | The MIME type. |
| DFIRe.Attachment.size | Number | File size in bytes. |
| DFIRe.Attachment.category | String | Attachment category. |
| DFIRe.Attachment.case | Number | The associated case ID. |
| DFIRe.Attachment.item | String | The associated item UUID. |
| DFIRe.Attachment.hash_sha256 | String | SHA-256 hash of the plaintext file. |
| DFIRe.Attachment.uploaded_by_name | String | Who uploaded the file. |
| DFIRe.Attachment.uploaded_at | Date | Upload timestamp. |

### dfire-attachment-get

***
Get details of a specific attachment.

#### Base Command

`dfire-attachment-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachment_id | The attachment ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Attachment.id | Number | The attachment ID. |
| DFIRe.Attachment.filename | String | The filename. |
| DFIRe.Attachment.mime_type | String | The MIME type. |
| DFIRe.Attachment.size | Number | File size in bytes. |
| DFIRe.Attachment.category | String | Attachment category. |
| DFIRe.Attachment.description | String | User-provided description. |
| DFIRe.Attachment.hash_sha256 | String | SHA-256 hash of the plaintext file. |
| DFIRe.Attachment.status | String | Upload/encryption status. |
| DFIRe.Attachment.storage_location | String | Storage backend \(local, s3, smb\). |
| DFIRe.Attachment.uploaded_at | Date | Upload timestamp. |

### dfire-attachment-upload

***
Upload a file as an attachment to a case or evidence item.

#### Base Command

`dfire-attachment-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the file to upload. | Required |
| case_id | Case ID to associate the attachment with. | Optional |
| item_uuid | Evidence item UUID to associate the attachment with. | Optional |
| filename | Override the filename (defaults to the uploaded file name). | Optional |
| category | Attachment category. `general` routes to the encrypted file store and is what most playbooks want. `evidence` is reserved for evidence photos and routes to the image gallery, not the file store. Possible values are: general, evidence. Default is general. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Attachment.id | Number | The created attachment ID. |
| DFIRe.Attachment.filename | String | The filename. |
| DFIRe.Attachment.size | Number | File size in bytes. |

### dfire-attachment-delete

***
Delete an attachment.

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
List timeline events for a case (newest first).

#### Base Command

`dfire-timeline-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.TimelineEvent.id | Number | The event ID. |
| DFIRe.TimelineEvent.event_type | String | The event type. |
| DFIRe.TimelineEvent.subject | String | The event subject. |
| DFIRe.TimelineEvent.details | String | The event details. |
| DFIRe.TimelineEvent.event_datetime | Date | When the event occurred. |
| DFIRe.TimelineEvent.created_by_name | String | Who created the event. |

### dfire-timeline-create

***
Add a manual timeline event to a case.

#### Base Command

`dfire-timeline-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| subject | The event subject line. | Required |
| details | The event description. | Optional |
| event_datetime | When the event occurred (ISO 8601). Defaults to now. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.TimelineEvent.id | Number | The created event ID. |
| DFIRe.TimelineEvent.subject | String | The event subject. |
| DFIRe.TimelineEvent.event_datetime | Date | The event timestamp. |

### dfire-user-list

***
List users in the DFIRe tenant. Useful for looking up user IDs for assignments.

#### Base Command

`dfire-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.User.id | Number | The user ID. |
| DFIRe.User.username | String | The username. |
| DFIRe.User.full_name | String | The user's full name. |
| DFIRe.User.email | String | The user's email. |
| DFIRe.User.is_active | Boolean | Whether the user is active. |
| DFIRe.User.groups | Unknown | Groups the user belongs to. |

### dfire-case-indicator-list

***
List indicators associated with a case.

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
| DFIRe.CaseIndicator.indicator.value | String | The IOC value. |
| DFIRe.CaseIndicator.indicator.stix_type | String | STIX type. |
| DFIRe.CaseIndicator.context | String | Case-private notes about this IOC. |
| DFIRe.CaseIndicator.source | String | How the indicator was added. |
| DFIRe.CaseIndicator.created_at | Date | Association timestamp. |
| DFIRe.CaseIndicator.case_count | Number | Total cases this indicator appears in. |

### dfire-case-indicator-add

***
Add an indicator to a case. Creates the indicator if it does not exist.

#### Base Command

`dfire-case-indicator-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| value | The IOC value. | Required |
| stix_type | STIX 2.1 SCO type. Possible values are: ipv4-addr, ipv6-addr, domain-name, url, email-addr, email-message, file, process, windows-registry-key, network-traffic, user-account, mac-addr, software, artifact, autonomous-system, directory, mutex, x509-certificate. | Required |
| classification | IOC classification. Possible values are: unknown, benign, suspicious, malicious. Default is unknown. | Optional |
| confidence | Confidence level. Possible values are: low, medium, high. Default is low. | Optional |
| tlp | TLP designation. Possible values are: clear, green, amber, amber_strict, red. Default is amber. | Optional |
| context | Case-private notes about this IOC. | Optional |
| tags | Comma-separated tags. | Optional |
| source | How this IOC was obtained. Possible values are: manual, automated, threat_intel, sandbox, enrichment, import. | Optional |
| source_reference | Free-form reference identifying the source (URL, ticket, report name, etc.). | Optional |
| valid_until | Auto-revoke after this ISO-8601 datetime (e.g. "2026-12-31T00:00:00Z"). | Optional |
| decompose | Whether to auto-decompose the indicator (URL→domain, email→domain). Possible values are: true, false. Default is true. | Optional |
| publish | Whether to publish the indicator immediately after creation. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseIndicator.id | Number | The association ID. |
| DFIRe.CaseIndicator.indicator.id | Number | The indicator ID. |
| DFIRe.CaseIndicator.indicator.value | String | The IOC value. |

### dfire-case-indicator-remove

***
Remove an indicator association from a case.

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
Extract candidate IOCs from a block of text. Returns suggestions only — does not add them to any case.

#### Base Command

`dfire-ioc-extract`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Text to scan for IOCs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IOCExtraction.candidates | Unknown | List of extracted IOC candidates. |

### dfire-indicator-check

***
Batch-check whether IOCs already exist in the global registry.

#### Base Command

`dfire-indicator-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | JSON array of {value, stix_type} objects (mutually exclusive with values+stix_type). | Optional |
| values | Comma-separated IOC values to check (used with stix_type). | Optional |
| stix_type | STIX type to use when checking the values arg. Possible values are: ipv4-addr, ipv6-addr, domain-name, url, email-addr, email-message, file, process, windows-registry-key, network-traffic, user-account, mac-addr, software, artifact, autonomous-system, directory, mutex, x509-certificate. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IndicatorCheck.results | Unknown | Existence/metadata for each submitted indicator. |

### dfire-indicator-enrich

***
Trigger external enrichment for an indicator.

#### Base Command

`dfire-indicator-enrich`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |
| providers | Comma-separated provider names (omit to run all applicable). | Optional |
| force | Re-enrich even if cached results exist. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |

### dfire-indicator-enrichment-list

***
Get cached enrichment results for an indicator.

#### Base Command

`dfire-indicator-enrichment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Enrichment.enrichments | Unknown | Enrichment records. |

### dfire-indicator-publish

***
Publish an indicator (make it visible to TAXII consumers and STIX exports).

#### Base Command

`dfire-indicator-publish`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.is_published | Boolean | Whether the indicator is published. |

### dfire-indicator-unpublish

***
Unpublish an indicator.

#### Base Command

`dfire-indicator-unpublish`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.is_published | Boolean | Whether the indicator is published. |

### dfire-indicator-revoke

***
Revoke an indicator.

#### Base Command

`dfire-indicator-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.is_revoked | Boolean | Whether the indicator is revoked. |

### dfire-indicator-unrevoke

***
Unrevoke an indicator.

#### Base Command

`dfire-indicator-unrevoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.is_revoked | Boolean | Whether the indicator is revoked. |

### dfire-indicator-decompose

***
Auto-decompose an indicator (URL→domain, email→domain, etc.).

#### Base Command

`dfire-indicator-decompose`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |

### dfire-indicator-add-tags

***
Merge a list of tags into the indicator's existing tag set.

#### Base Command

`dfire-indicator-add-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The indicator ID. | Required |
| tags | Comma-separated tags to add. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Indicator.id | Number | The indicator ID. |
| DFIRe.Indicator.tags | Unknown | Updated tag list. |

### dfire-indicator-correlated-list

***
List indicators that appear in multiple cases.

#### Base Command

`dfire-indicator-correlated-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IndicatorCorrelated.results | Unknown | Correlated indicators across cases. |

### dfire-indicator-bulk-classify

***
Bulk-update classification for multiple indicators.

#### Base Command

`dfire-indicator-bulk-classify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | Comma-separated indicator IDs. | Required |
| classification | New classification. Possible values are: unknown, benign, suspicious, malicious. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | Bulk operation result. |

### dfire-indicator-bulk-confidence

***
Bulk-update confidence for multiple indicators.

#### Base Command

`dfire-indicator-bulk-confidence`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | Comma-separated indicator IDs. | Required |
| confidence | New confidence level. Possible values are: low, medium, high. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | Bulk operation result. |

### dfire-indicator-bulk-tag

***
Bulk add/remove/set tags on multiple indicators.

#### Base Command

`dfire-indicator-bulk-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | Comma-separated indicator IDs. | Required |
| tags | Comma-separated tags. | Required |
| mode | How to apply the tags. Possible values are: add, remove, set. Default is add. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | Bulk operation result. |

### dfire-indicator-bulk-tlp

***
Bulk-update TLP designation for multiple indicators.

#### Base Command

`dfire-indicator-bulk-tlp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | Comma-separated indicator IDs. | Required |
| tlp | New TLP designation. Possible values are: clear, green, amber, amber_strict, red. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | Bulk operation result. |

### dfire-indicator-bulk-publish

***
Bulk-publish indicators.

#### Base Command

`dfire-indicator-bulk-publish`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | Comma-separated indicator IDs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkPublishResponse.published_count | Number | Number of indicators published. |
| DFIRe.BulkPublishResponse.skipped_revoked | Number | Number skipped because revoked. |
| DFIRe.BulkPublishResponse.skipped_red | Number | Number skipped because TLP:RED. |

### dfire-indicator-bulk-revoke

***
Bulk-revoke indicators.

#### Base Command

`dfire-indicator-bulk-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | Comma-separated indicator IDs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | Bulk operation result. |

### dfire-indicator-bulk-delete

***
Bulk-delete indicators.

#### Base Command

`dfire-indicator-bulk-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | Comma-separated indicator IDs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.BulkResult | Unknown | Bulk operation result. |

### dfire-case-generate-summary

***
Trigger AI-generated executive summary for a case.

#### Base Command

`dfire-case-generate-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseSummary | Unknown | Summary result. |

### dfire-case-chat

***
Send a chat message to the case AI assistant.

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
| DFIRe.CaseChat | Unknown | Chat response. |

### dfire-case-update-report

***
Update the text of an AI-generated report attached to a case (e.g. an executive summary).

#### Base Command

`dfire-case-update-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID the report belongs to. | Required |
| report_id | ID of the generated report to update. | Required |
| report_text | New report text content. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseReport | Unknown | Updated report. |

### dfire-case-can-report-list

***
List CAN (Case Activity Notice) reports for a case.

#### Base Command

`dfire-case-can-report-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CANReport.id | Number | CAN report ID. |

### dfire-case-can-report-generate

***
Generate a new CAN report for a case.

#### Base Command

`dfire-case-can-report-generate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| body | Optional JSON body describing the report parameters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CANReport.id | Number | Generated report ID. |

### dfire-case-investigation-report-get

***
Get the investigation report for a case.

#### Base Command

`dfire-case-investigation-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.InvestigationReport | Unknown | Investigation report. |

### dfire-case-investigation-report-generate

***
Generate AI content for a single section of a case's investigation report. Returns preview content; does not auto-save.

#### Base Command

`dfire-case-investigation-report-generate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| section_id | ID of the report section to generate content for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.InvestigationReport.content | String | Generated section content. |
| DFIRe.InvestigationReport.model | String | Model used to generate the content. |

### dfire-case-investigation-report-finalize

***
Finalize the investigation report for a case.

#### Base Command

`dfire-case-investigation-report-finalize`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.InvestigationReport | Unknown | Finalized investigation report. |

### dfire-case-investigation-report-ready-for-qa

***
Mark a single section of the investigation report as ready for QA review.

#### Base Command

`dfire-case-investigation-report-ready-for-qa`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| section_id | ID of the report section to mark ready for QA. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.InvestigationReport | Unknown | Investigation report section after the state change. |

### dfire-case-timeline-change-phase

***
Move a case to a new incident-response phase.

#### Base Command

`dfire-case-timeline-change-phase`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| phase_id | Target phase ID. | Optional |
| phase_name | Target phase name (used if phase_id is omitted). | Optional |
| note | Optional note explaining the phase change. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.TimelineEvent.id | Number | Created phase-change timeline event ID. |

### dfire-case-todo-list

***
List todos for a case.

#### Base Command

`dfire-case-todo-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | Todo ID. |
| DFIRe.CaseTodo.title | String | Todo title. |
| DFIRe.CaseTodo.status | String | Todo status. |

### dfire-case-todo-get

***
Get a single todo with full details.

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
| DFIRe.CaseTodo.id | Number | Todo ID. |

### dfire-case-todo-assign

***
Assign a todo to a user.

#### Base Command

`dfire-case-todo-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| todo_id | The todo ID. | Required |
| assignee_id | User ID of the assignee. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | Todo ID. |
| DFIRe.CaseTodo.assignee_name | String | Assignee display name. |

### dfire-case-todo-note-set

***
Set or replace the note on a todo.

#### Base Command

`dfire-case-todo-note-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| todo_id | The todo ID. | Required |
| note | New note content. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | Todo ID. |

### dfire-case-todo-attach-runbook

***
Attach a runbook to a todo.

#### Base Command

`dfire-case-todo-attach-runbook`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |
| todo_id | The todo ID. | Required |
| runbook_slug | Runbook slug to attach. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTodo.id | Number | Todo ID. |
| DFIRe.CaseTodo.runbook_slug | String | Attached runbook slug. |

### dfire-case-todo-detach-runbook

***
Detach the runbook from a todo.

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
| DFIRe.CaseTodo.id | Number | Todo ID. |

### dfire-case-timer-list

***
List SLA timers for a case.

#### Base Command

`dfire-case-timer-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.CaseTimer.id | Number | Timer ID. |
| DFIRe.CaseTimer.name | String | Timer name. |
| DFIRe.CaseTimer.framework | String | Compliance framework. |

### dfire-case-timer-get

***
Get a single SLA timer.

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
| DFIRe.CaseTimer.id | Number | Timer ID. |

### dfire-case-timer-complete

***
Mark a case SLA timer as complete.

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
| DFIRe.CaseTimer.id | Number | Timer ID. |

### dfire-case-timer-reset

***
Reset a case SLA timer.

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
| DFIRe.CaseTimer.id | Number | Timer ID. |

### dfire-case-get-by-number

***
Look up a case by its human-readable case number.

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
Resolve an 8-character item short ID to its full UUID and parent case ID.

#### Base Command

`dfire-item-resolve-short-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| short_id | First 8 characters of the item UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Item.uuid | String | The full item UUID. |
| DFIRe.Item.case | Number | The parent case ID. |

### dfire-incident-category-list

***
List ENISA incident categories (useful for picklists).

#### Base Command

`dfire-incident-category-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IncidentCategory.id | Number | Category ID. |
| DFIRe.IncidentCategory.name | String | Category name. |

### dfire-incident-phase-list

***
List configured incident-response phases.

#### Base Command

`dfire-incident-phase-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.IncidentPhase.id | Number | Phase ID. |
| DFIRe.IncidentPhase.name | String | Phase name. |

### dfire-outcome-verdict-list

***
List case outcome verdicts (true positive, false positive, etc.).

#### Base Command

`dfire-outcome-verdict-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.OutcomeVerdict.id | Number | Verdict ID. |
| DFIRe.OutcomeVerdict.name | String | Verdict name. |

### dfire-project-list

***
List projects.

#### Base Command

`dfire-project-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Project.id | Number | Project ID. |
| DFIRe.Project.name | String | Project name. |

### dfire-runbook-list

***
List available runbooks (used for todo runbook attachments).

#### Base Command

`dfire-runbook-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Runbook.slug | String | Runbook slug. |
| DFIRe.Runbook.name | String | Runbook name. |

### dfire-group-list

***
List user groups.

#### Base Command

`dfire-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DFIRe.Group.id | Number | Group ID. |
| DFIRe.Group.name | String | Group name. |
