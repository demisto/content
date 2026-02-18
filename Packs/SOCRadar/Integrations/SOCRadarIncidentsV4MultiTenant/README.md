# SOCRadar Incidents v4.0 Multi-Tenant

Fetch and manage security incidents from multiple companies using SOCRadar's Multi-Tenant Incident API. Designed for MSPs, MSSPs, and organizations managing multiple subsidiaries.

## Overview

SOCRadar is a digital risk protection platform that provides extended threat intelligence and brand protection capabilities. This Multi-Tenant integration enables XSOAR to ingest security incidents from multiple companies through a single integration instance, including:

- **Brand Protection**: Impersonating domains, phishing attacks, brand abuse
- **Cyber Threat Intelligence**: Stolen credentials, data leaks, malware infections
- **Attack Surface Management**: External exposure findings, misconfigurations
- **Dark Web Intelligence**: Compromised credentials, leaked data from dark web sources
- **Supply Chain Security**: Third-party risks and vendor security issues
  
## Multi-Tenant Features

### Centralized Multi-Company Management

- **Single Integration**: Monitor incidents from all your companies through one integration instance
- **Company Tracking**: Each alarm automatically includes company ID and company name
- **Smart Filtering**: Filter and manage incidents across companies or focus on specific ones

### Automatic Company ID Handling

- **Auto-Extraction**: When taking actions, company ID is automatically extracted from alarm data
- **No Manual Input**: You don't need to remember or specify company IDs for most operations
- **Override Capability**: Manually specify company ID when needed (advanced use cases)

### Company Visibility Control

- **Configurable Display**: Choose whether to show company information in incident details
- **Custom Fields**: Company ID and company name available in custom fields
- **Incident Naming**: Company information included in incident names for quick identification

---

## What's New in Multi-Tenant v4.0

### Multi-Tenant Specific

- **Multi-Tenant API Endpoint**: Uses `/multi_tenant/{multi-tenant-id}/incidents` for fetching
- **Company Information**: Each alarm includes both company_id and company_name
- **Smart Action Handling**: Automatically determines which company to act upon
- **Default Company Visibility**: Company info shown by default (can be disabled)

### Core Features (from v4.0)

- **Multi-Status Filtering**: Select multiple statuses (OPEN, CLOSED, ON_HOLD) simultaneously
- **Epoch Time Precision**: Second-level accuracy for incident fetching - zero duplicates
- **Reverse Pagination**: Fetches newest incidents first for better performance
- **Dynamic Content Extraction**: Automatically extracts alarm-specific fields regardless of type
- **Enhanced Deduplication**: Two-layer protection prevents duplicate incidents

### Technical Improvements

- Interval-based fetching with overlap protection
- Configurable content and entity inclusion
- Comprehensive debug logging
- Better error handling and recovery
- Intelligent company ID extraction from incident context

---

## Key Differences: Standard vs Multi-Tenant

| **Feature** | **Standard v4.0** | **Multi-Tenant v4.0** |
| --- | --- | --- |
| **Configuration** | Company ID + API Key | Multi-Tenant ID + API Key |
| **Fetch Endpoint** | `/company/{id}/incidents/v4` | `/multi_tenant/{id}/incidents` |
| **Company Data** | Single company (implicit) | Multiple companies (explicit) |
| **Company ID in Actions** | Uses configured company ID | Auto-extracted from alarm |
| **Company Visibility** | Optional (default: hidden) | Optional (default: visible) |
| **Use Case** | Single organization | MSPs, MSSPs, multi-subsidiary |

---

## Prerequisites

### Required

- SOCRadar account with Multi-Tenant Incident API access
- Multi-Tenant ID from SOCRadar platform
- API Key from SOCRadar platform
- XSOAR 6.x or later

### API Access

To obtain your API credentials:

1. Log in to [SOCRadar Platform](https://platform.socradar.com)
2. Reach out support team to get MSSP API Key

---

## Configuration

### Integration Settings

| **Parameter** | **Required** | **Default** | **Description** |
| --- | --- | --- | --- |
| **Server URL** | Yes | `https://platform.socradar.com/api` | SOCRadar API base URL |
| **API Key** | Yes | - | Your Multi-Tenant API Key from SOCRadar |
| **Multi-Tenant ID** | Yes | - | Your Multi-Tenant ID (integer) |
| **Fetch incidents** | No | False | Enable automatic incident fetching |
| **Incident type** | No | - | XSOAR incident type to create |
| **Max incidents per fetch** | No | 10000 | Maximum incidents per fetch cycle |
| **First fetch time** | No | 3 days | Initial time range for first fetch |
| **Fetch Interval (Minutes)** | No | 1 | Time window for subsequent fetches |

### Filtering Options

| **Parameter** | **Type** | **Description** |
| --- | --- | --- |
| **Status Filter** | Multi-select | Select one or more: OPEN, CLOSED, ON_HOLD |
| **Severity** | Multi-select | Filter by: LOW, MEDIUM, HIGH, CRITICAL |
| **Alarm Type IDs** | Text | Comma-separated list of type IDs to include |
| **Excluded Alarm Type IDs** | Text | Comma-separated list of type IDs to exclude |
| **Main Alarm Types** | Text | Comma-separated main types (e.g., "Brand Protection") |
| **Alarm Sub Types** | Text | Comma-separated sub types |

---

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### socradar-change-alarm-status

***
Change the status of one or more alarms.

#### Base Command

`socradar-change-alarm-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_ids | Comma-separated list of alarm IDs to update. | Required |
| status_reason | New status reason for the alarms. Possible values are: OPEN, INVESTIGATING, RESOLVED, PENDING_INFO, LEGAL_REVIEW, VENDOR_ASSESSMENT, FALSE_POSITIVE, DUPLICATE, PROCESSED_INTERNALLY, MITIGATED, NOT_APPLICABLE. | Required |
| comments | Optional comments explaining the status change. | Optional |
| company_id | Company ID for the alarm. If not provided, will be auto-fetched from alarm data. Can also use ${incident.socradarcompanyid} from incident fields. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadar.Alarm.ID | String | Alarm ID. |
| SOCRadar.Alarm.Status | String | New alarm status. |

---

### socradar-mark-false-positive

***
Mark an alarm as false positive.

#### Base Command

`socradar-mark-false-positive`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | Alarm ID to mark as false positive. | Required |
| comments | Optional comments explaining why this is a false positive. Default is False positive. | Optional |
| company_id | Company ID for the alarm. If not provided, will be auto-fetched from alarm data. Can also use ${incident.socradarcompanyid} from incident fields. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadar.Alarm.ID | String | Alarm ID. |
| SOCRadar.Alarm.Status | String | New alarm status. |

---

### socradar-mark-resolved

***
Mark an alarm as resolved.

#### Base Command

`socradar-mark-resolved`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | Alarm ID to mark as resolved. | Required |
| comments | Optional comments explaining the resolution. Default is Resolved. | Optional |
| company_id | Company ID for the alarm. If not provided, will be auto-fetched from alarm data. Can also use ${incident.socradarcompanyid} from incident fields. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadar.Alarm.ID | String | Alarm ID. |
| SOCRadar.Alarm.Status | String | New alarm status. |

---

### socradar-add-comment

***
Add a comment to an alarm.

#### Base Command

`socradar-add-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | Alarm ID to add comment to. | Required |
| user_email | Email address of the user adding the comment. | Required |
| comment | Comment text to add. | Required |
| company_id | Company ID for the alarm. If not provided, will be auto-fetched from alarm data. Can also use ${incident.socradarcompanyid} from incident fields. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadar.Alarm.ID | String | Alarm ID. |

---

### socradar-add-assignee

***
Add the assignee(s) of an alarm.

#### Base Command

`socradar-add-assignee`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | Alarm ID to add assignee for. | Required |
| user_emails | Comma-separated list of user email addresses to assign. | Required |
| company_id | Company ID for the alarm. If not provided, will be auto-fetched from alarm data. Can also use ${incident.socradarcompanyid} from incident fields. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadar.Alarm.ID | String | Alarm ID. |
| SOCRadar.Alarm.Assignees | String | New assignees. |

---

### socradar-add-tag

***
Add or remove a tag from an alarm.

#### Base Command

`socradar-add-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | Alarm ID to add/remove tag for. | Required |
| tag | Tag name to add or remove. | Required |
| company_id | Company ID for the alarm. If not provided, will be auto-fetched from alarm data. Can also use ${incident.socradarcompanyid} from incident fields. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadar.Alarm.ID | String | Alarm ID. |
| SOCRadar.Alarm.Tags | String | Alarm tags. |

---

### socradar-test-fetch

***
Test incident fetching to verify alarms are available and date parsing works correctly.

#### Base Command

`socradar-test-fetch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of incidents to test fetch (default 5). Default is 5. | Optional |
| first_fetch | Test date range (e.g., "3 days", "7 days"). Default is 3 days. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadar.TestFetch.TotalCount | Number | Total number of incidents found. |
| SOCRadar.TestFetch.SampleIncidents | Unknown | Sample incidents for testing. |
| SOCRadar.TestFetch.StartDate | String | Parsed start date used for the test. |
| SOCRadar.TestFetch.TotalRecords | Number | Total number of incidents from service. |
| SOCRadar.TestFetch.TotalPages | Number | Total number of pages of incidents from service. |

---

## License

This integration is provided as part of the Cortex XSOAR content pack.
