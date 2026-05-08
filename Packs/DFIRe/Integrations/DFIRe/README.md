# DFIRe

[DFIRe](https://dfire.fi/) is a self-hosted Digital Forensics and Incident Response (DFIR) case management platform built for security professionals. It provides structured case management, evidence tracking with chain of custody, IOC indicator management, and incident response workflows aligned with the NIST Incident Response framework — all running on your own infrastructure with AES-256 encryption.

This integration connects Cortex XSIAM to a DFIRe instance, enabling automated case creation and updates, bi-directional IOC indicator synchronisation, evidence item tracking, and timeline enrichment directly from playbooks.

## Configure DFIRe on Cortex XSIAM

1. Navigate to **Settings** → **Integrations** → **Servers & Services**.
2. Search for **DFIRe**.
3. Click **Add instance** and fill in the required fields:

| Parameter | Description | Required |
|-----------|-------------|----------|
| Server URL | URL of your DFIRe instance (e.g. `https://dfire.example.com`) | Yes |
| API Key | API key generated in DFIRe System Settings | Yes |
| Trust any certificate (not secure) | Skip TLS verification for self-signed certs | No |
| Use system proxy settings | Route requests through the configured proxy | No |

4. Click **Test** to verify connectivity.

### Generating an API Key in DFIRe

In your DFIRe instance, go to **System Settings** → **Integrations** and create a new API key. Scope it to the collections and permissions required by your playbooks.

## Commands

You can execute these commands from the Cortex XSIAM CLI or use them in playbooks.

---

### dfire-search

Search across all DFIRe data (cases, indicators, notes, evidence items). Supports `AND`, `OR`, and `NOT` operators.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| query | Search query string. Supports boolean operators. | Yes |
| limit | Maximum number of results to return. | No |

---

### dfire-case-list

List cases from DFIRe.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| limit | Maximum number of cases to return. | No |
| offset | Pagination offset. | No |

---

### dfire-case-get

Get details of a specific case.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case. | Yes |

---

### dfire-case-create

Create a new case in DFIRe.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| name | Case name. | Yes |
| case_type_id | Case type ID (use `dfire-case-type-list` to look up). | Yes |
| severity | Severity level of the case. | No |
| description | Case description. | No |
| assignee_id | User ID to assign the case to. | No |

---

### dfire-case-update

Update an existing case in DFIRe.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case to update. | Yes |
| name | New case name. | No |
| severity | New severity level. | No |
| description | New description. | No |
| assignee_id | New assignee user ID. | No |

---

### dfire-case-delete

Delete a case from DFIRe.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case to delete. | Yes |

---

### dfire-case-note-list

List notes for a case.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case. | Yes |

---

### dfire-case-note-create

Create a note on a case.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case. | Yes |
| content | Note content (Markdown supported). | Yes |

---

### dfire-indicator-list

List indicators from the global IOC registry.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| limit | Maximum number of indicators to return. | No |
| offset | Pagination offset. | No |

---

### dfire-indicator-get

Get details of a specific indicator.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| indicator_id | The UUID of the indicator. | Yes |

---

### dfire-indicator-create

Create a new indicator in the global IOC registry.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| type | Indicator type (e.g. `ip`, `domain`, `hash`, `url`). | Yes |
| value | Indicator value. | Yes |
| description | Description of the indicator. | No |
| tlp | Traffic Light Protocol level. | No |

---

### dfire-indicator-update

Update an existing indicator.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| indicator_id | The UUID of the indicator to update. | Yes |
| description | New description. | No |
| tlp | New TLP level. | No |

---

### dfire-indicator-delete

Delete an indicator from the global IOC registry.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| indicator_id | The UUID of the indicator to delete. | Yes |

---

### dfire-item-list

List evidence items, optionally filtered by case.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | Filter by case UUID. | No |
| limit | Maximum number of items to return. | No |

---

### dfire-item-get

Get details of a specific evidence item.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| item_id | The UUID of the evidence item. | Yes |

---

### dfire-item-create

Create a new evidence item on a case.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case. | Yes |
| name | Evidence item name. | Yes |
| item_type_id | Evidence type ID (use `dfire-item-type-list` to look up). | Yes |
| description | Description of the evidence item. | No |

---

### dfire-attachment-list

List attachments, optionally filtered by evidence item UUID.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| item_id | Filter by evidence item UUID. | No |

---

### dfire-attachment-upload

Upload a file as an attachment to a case or evidence item. Files are stored with AES-256 encryption.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| entry_id | XSOAR/XSIAM War Room entry ID of the file to upload. | Yes |
| case_id | The UUID of the case to attach the file to. | No |
| item_id | The UUID of the evidence item to attach the file to. | No |

---

### dfire-attachment-delete

Delete an attachment.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| attachment_id | The UUID of the attachment to delete. | Yes |

---

### dfire-timeline-list

List timeline events for a case (newest first).

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case. | Yes |

---

### dfire-timeline-create

Add a manual timeline event to a case.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case. | Yes |
| title | Event title. | Yes |
| description | Event description. | No |
| event_time | ISO 8601 timestamp of the event. | No |

---

### dfire-user-list

List users in the DFIRe tenant. Useful for looking up user IDs for case assignments.

---

### dfire-case-type-list

List available case types and their IDs.

---

### dfire-item-type-list

List available evidence item types and their IDs.

---

### dfire-item-flag-list

List available item flags and their IDs.

---

### dfire-case-indicator-list

List indicators associated with a specific case.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case. | Yes |

---

### dfire-case-indicator-add

Add an indicator to a case. Creates the indicator in the global IOC registry if it does not already exist.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case. | Yes |
| type | Indicator type (e.g. `ip`, `domain`, `hash`, `url`). | Yes |
| value | Indicator value. | Yes |

---

### dfire-case-indicator-remove

Remove an indicator association from a case.

**Arguments**

| Argument | Description | Required |
|----------|-------------|----------|
| case_id | The UUID of the case. | Yes |
| indicator_id | The UUID of the indicator to remove. | Yes |
