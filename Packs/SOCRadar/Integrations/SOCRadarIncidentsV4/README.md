# SOCRadar Incidents v4.0

Fetch and manage security incidents from SOCRadar's Incident API v4 with advanced filtering, multi-status selection, and comprehensive incident enrichment.

![SOCRadar Logo](https://raw.githubusercontent.com/demisto/content/master/Packs/SOCRadar/doc_files/socradar-logo.png)

## Overview

SOCRadar is a digital risk protection platform that provides extended threat intelligence and brand protection capabilities. This integration enables XSOAR to ingest security incidents from SOCRadar's Incident API v4, including:

- **Brand Protection**: Impersonating domains, phishing attacks, brand abuse
- **Cyber Threat Intelligence**: Stolen credentials, data leaks, malware infections
- **Attack Surface Management**: External exposure findings, misconfigurations
- **Dark Web Intelligence**: Compromised credentials, leaked data from dark web sources
- **Supply Chain Security**: Third-party risks and vendor security issues

---

## What's New in v4.0

### Major Enhancements

- **Multi-Status Filtering**: Select multiple statuses (OPEN, CLOSED, ON_HOLD) simultaneously
- **Epoch Time Precision**: Second-level accuracy for incident fetching - zero duplicates
- **Reverse Pagination**: Fetches newest incidents first for better performance
- **Dynamic Content Extraction**: Automatically extracts alarm-specific fields regardless of type
- **Parametric Company ID Display**: Control whether company ID appears in incidents
- **Enhanced Deduplication**: Two-layer protection prevents duplicate incidents
- **New Commands**: Ask analyst, change severity, and more

### Technical Improvements

- Interval-based fetching with overlap protection
- Configurable content and entity inclusion
- Integer company ID with validation
- Comprehensive debug logging
- Better error handling and recovery

## Key Features

### Incident Fetching
- Fetch incidents with configurable interval (default: 1 minute)
- Support for date ranges and epoch timestamps
- Automatic deduplication (tracks last 1000 alarm IDs)
- Reverse pagination for optimal performance

### Flexible Filtering
- **Multi-Status Selection**: OPEN, CLOSED, ON_HOLD (multi-select)
- **Severity Levels**: LOW, MEDIUM, HIGH, CRITICAL
- **Alarm Types**: Filter by main type, sub-type, or type ID
- **Custom Filters**: Tags, assignees, date ranges

### Rich Incident Data
- Dynamic CustomFields based on alarm type
- Configurable content extraction (varies by alarm type)
- Optional entity details inclusion
- Optional company ID visibility

### Incident Management
- Change alarm status (11 status options)
- Add comments to alarms
- Change assignees
- Add/remove tags
- Request analyst assistance
- Modify severity levels
- Mark as false positive/resolved

## Prerequisites

### Required
- SOCRadar account with Incident API access
- API Key from SOCRadar platform
- Company ID
- XSOAR 6.x or later

### API Access
To obtain your API credentials:

1. Log in to [SOCRadar Platform](https://platform.socradar.com)
2. Navigate to **Settings → API & Integrations**
3. Go to **API Options** page
4. Copy your **Company API Key** (for Incident API)
5. Note your **Company ID**


## Configuration

### Integration Settings

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| **Server URL** | Yes | `https://platform.socradar.com/api` | SOCRadar API base URL |
| **API Key** | Yes | - | Your Company API Key from SOCRadar |
| **Company ID** | Yes | - | Your Company ID (integer) |
| **Fetch incidents** | No | False | Enable automatic incident fetching |
| **Incident type** | No | - | XSOAR incident type to create |
| **Max incidents per fetch** | No | 10000 | Maximum incidents per fetch cycle |
| **First fetch time** | No | 3 days | Initial time range for first fetch |
| **Fetch Interval (Minutes)** | No | 1 | Time window for subsequent fetches |

### Filtering Options

| Parameter | Type | Description |
|-----------|------|-------------|
| **Status Filter** | Multi-select | Select one or more: OPEN, CLOSED, ON_HOLD |
| **Severity** | Multi-select | Filter by: LOW, MEDIUM, HIGH, CRITICAL |
| **Alarm Type IDs** | Text | Comma-separated list of type IDs to include |
| **Excluded Alarm Type IDs** | Text | Comma-separated list of type IDs to exclude |
| **Main Alarm Types** | Text | Comma-separated main types (e.g., "Brand Protection") |
| **Alarm Sub Types** | Text | Comma-separated sub types |

### Content Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| **Include Alarm Content** | True | Extract content fields to CustomFields |
| **Include Related Entities** | True | Include entity details in CustomFields |
| **Include Company ID** | False | Show company ID in incidents (for multi-tenant) |

---

## Installation

### From XSOAR Marketplace

1. Navigate to **Settings → Marketplace**
2. Search for "SOCRadar"
3. Click **Install**
4. Configure integration instance

### From GitHub (Manual)

```bash
# Clone the content repository
git clone https://github.com/demisto/content.git
cd content/Packs/SOCRadar

# Copy to your XSOAR instance
# Upload via Settings → Integrations → Upload
```

---

## Setup Guide

### Step 1: Create Integration Instance

1. Navigate to **Settings → Integrations → Servers & Services**
2. Search for "SOCRadar Incidents v4"
3. Click **Add instance**

### Step 2: Configure Basic Settings

```
Name: SOCRadar Production
Server URL: https://platform.socradar.com/api
API Key: [Your API Key from SOCRadar]
Company ID: [Your Company ID]
```

### Step 3: Configure Fetching (Optional)

```
✓ Fetches incidents
Incident type: SOCRadar Incident
Max incidents per fetch: 10000
First fetch time: 3 days
Fetch Interval: 1 (minutes)
```

### Step 4: Configure Filters (Optional)

```
Status Filter:
  ☑ OPEN
  ☐ CLOSED
  ☐ ON_HOLD

Content Options:
  ☑ Include Alarm Content in Custom Fields
  ☑ Include Related Entities Details
  ☐ Include Company ID in Incidents
```

### Step 5: Test Connection

Click **Test** button to verify:
- API connectivity
- Authentication
- Company ID validity

## Commands

### Incident Management

#### `socradar-change-alarm-status`
Change the status of one or more alarms.

**Arguments:**
- `alarm_ids` (Required): Comma-separated alarm IDs (e.g., "12345,67890")
- `status_reason` (Required): New status
  - `OPEN`, `INVESTIGATING`, `RESOLVED`, `PENDING_INFO`
  - `LEGAL_REVIEW`, `VENDOR_ASSESSMENT`, `FALSE_POSITIVE`
  - `DUPLICATE`, `PROCESSED_INTERNALLY`, `MITIGATED`, `NOT_APPLICABLE`
- `comments` (Optional): Status change comments
- `company_id` (Optional): Override default company ID

**Example:**
```
!socradar-change-alarm-status alarm_ids="81171696" status_reason="INVESTIGATING" comments="Under review"
```

**From Incident Context:**
```
!socradar-change-alarm-status alarm_ids=${incident.dbotMirrorId} status_reason="RESOLVED"
```

#### `socradar-mark-false-positive`
Mark alarm as false positive (shortcut command).

**Arguments:**
- `alarm_id` (Required): Alarm ID
- `comments` (Optional): Reason for false positive
- `company_id` (Optional): Override default company ID

**Example:**
```
!socradar-mark-false-positive alarm_id="81171696" comments="Not a real threat"
```
#### `socradar-mark-resolved`
Mark alarm as resolved (shortcut command).

**Arguments:**
- `alarm_id` (Required): Alarm ID
- `comments` (Optional): Resolution notes
- `company_id` (Optional): Override default company ID

**Example:**
```
!socradar-mark-resolved alarm_id="81171696" comments="Issue fixed"
```

### For Notes

#### `socradar-add-comment`
Add a comment to an alarm.

**Arguments:**
- `alarm_id` (Required): Alarm ID
- `user_email` (Required): Email of user posting comment
- `comment` (Required): Comment text
- `company_id` (Optional): Override default company ID

**Example:**
```
!socradar-add-comment alarm_id="81171696" user_email="analyst@company.com" comment="Investigating with security team"
```

#### `socradar-ask-analyst`
Request assistance from SOCRadar analyst.

**Arguments:**
- `alarm_id` (Required): Alarm ID
- `comment` (Required): Message for analyst
- `company_id` (Optional): Override default company ID

**Example:**
```
!socradar-ask-analyst alarm_id="81171696" comment="Need help analyzing this credential leak"
```


### Assignment & Organization

#### `socradar-change-assignee`
Change alarm assignee(s).(User must be defined the same company)

**Arguments:**
- `alarm_id` (Required): Alarm ID
- `user_emails` (Required): Comma-separated email addresses
- `company_id` (Optional): Override default company ID

**Example:**
```
!socradar-change-assignee alarm_id="81171696" user_emails="analyst1@company.com,analyst2@company.com"
```

#### `socradar-add-tag`
Add or remove a tag from alarm.

**Arguments:**
- `alarm_id` (Required): Alarm ID
- `tag` (Required): Tag name
- `company_id` (Optional): Override default company ID

**Example:**
```
!socradar-add-tag alarm_id="81171696" tag="reviewed"
```

#### `socradar-change-severity`
Modify alarm severity level.

**Arguments:**
- `alarm_id` (Required): Alarm ID
- `severity` (Required): New severity (LOW, MEDIUM, HIGH, CRITICAL)
- `company_id` (Optional): Override default company ID

**Example:**
```
!socradar-change-severity alarm_id="81171696" severity="HIGH"
```

### Testing

#### `socradar-test-fetch`
Test the fetch incidents functionality without creating incidents.

**Arguments:**
- `first_fetch` (Optional): Time range to test (default: "3 days")
- `limit` (Optional): Number of incidents to fetch (default: 5)

**Example:**
```
!socradar-test-fetch first_fetch="1 hour" limit="10"
```

**Output:**
```
Found 150 incident(s) from 2024-12-20!
Total available: 1000 records across 10 pages
Using REVERSE PAGINATION (page 10 → page 1)

Sample incidents:
- [81171696] HIGH | OPEN | example.com
  Company: 789 | Type: Brand Protection / Impersonating Domain
  
- [81171697] CRITICAL | OPEN | admin@company.com
  Company: 789 | Type: Cyber Threat Intelligence / Stolen Credentials
```

---

## Custom Fields

The integration creates these CustomFields in XSOAR incidents:

### Standard Fields (Always Present)
- `socradaralarmid`: Alarm ID
- `socradarstatus`: Current status
- `socradarasset`: Affected asset
- `socradaralarmtype`: Main alarm type
- `socradaralarmsubtype`: Alarm sub-type
- `socradaralarmtypeid`: Type ID
- `socradartags`: Comma-separated tags
- `socradarrisklevel`: Risk level
- `socradaralarmtext`: Alarm description (truncated to 1000 chars)

### Optional Fields
- `socradarcompanyid`: Company ID (if "Include Company ID" enabled)
- `socradarentities`: Related entities (if "Include Entities" enabled)

### Dynamic Content Fields (if "Include Content" enabled)
Content structure varies by alarm type. Examples:

**Impersonating Domain:**
- `socradarcontentdns_information`
- `socradarcontentwhois_information`
- `socradarcontentdomain_status`

**Stolen Credentials:**
- `socradarcontentcredential_details`
- `socradarcontentlog_content_link`
- `socradarcontentmalware_family`

**Data Leak:**
- `socradarcontentsource_full_content`
- `socradarcontentcompromised_emails`
- `socradarcontentcompromised_domains`

---

## Use Cases

### 1. Brand Protection

**Scenario:** Detect and respond to phishing domains impersonating your brand.

**Configuration:**
```
Main Alarm Types: Brand Protection
Status Filter: OPEN
Severity: HIGH, CRITICAL
```

**Automation:**
```python
# Get incident
incident = demisto.incident()
alarm_id = incident.get('dbotMirrorId')

# Check domain details
domain_info = incident.get('CustomFields', {}).get('socradarcontentdns_information')

# Take action
demisto.executeCommand('socradar-change-assignee', {
    'alarm_id': alarm_id,
    'user_emails': 'legal@company.com'
})
```


### 2. Multi-Tenant Operations (MSSP)

**Scenario:** Manage incidents for multiple customers.

**Configuration:**
```
Instance 1:
- Company ID: 789
- Include Company ID: ✓ YES

Instance 2:
- Company ID: 456
- Include Company ID: ✓ YES
```

**Automation:**
```python
# Company ID is visible in CustomFields
company_id = incident.get('CustomFields', {}).get('socradarcompanyid')

# Route to appropriate team
if company_id == "789":
    assign_to = "team-a@company.com"
else:
    assign_to = "team-b@company.com"

demisto.executeCommand('socradar-change-assignee', {
    'alarm_id': incident.get('dbotMirrorId'),
    'user_emails': assign_to
})
```

## Troubleshooting

### No Incidents Fetched

**Check:**
1. **Test connection**: Click "Test" button
2. **Date range**: Increase "First fetch time" to "7 days"
3. **Filters**: Remove status/severity filters temporarily
4. **Debug logs**: Check XSOAR server logs

**Debug Command:**
```
!socradar-test-fetch first_fetch="7 days" limit="10"
```

Look for:
```
[SOCRadar V4.0] Total available: 0 records
```
If 0 records, no alarms match your filters.


### Duplicate Incidents

This should NOT happen in v4.0! If you see duplicates:

1. **Check fetch interval**: Should be ≥ 1 minute
2. **Check logs** for deduplication stats:
   ```
   [SOCRadar V4.0] Page 1: Created 5 NEW incidents, skipped 95 duplicates
   ```
3. **Verify epoch time usage**:
   ```
   [SOCRadar V4.0] Time window (epoch seconds): 1734465600 to 1734465660
   ```

If duplicates persist, contact support with debug logs.

### API Errors

**401 Unauthorized:**
- Verify API Key is correct

**404 Not Found:**
- Verify Company ID is correct (integer, not string)
- Check endpoint URLs in debug logs

**Rate Limiting:**
- Reduce fetch frequency
- Decrease "Max incidents per fetch"


### Missing CustomFields

**If dynamic content fields not appearing:**

1. Verify "Include Alarm Content" is **enabled**
2. Create CustomFields manually in XSOAR:
   - Settings → Advanced → Fields
   - Add fields with type "Short Text"
   - Prefix: `socradarcontent`

**If entities not appearing:**
1. Verify "Include Related Entities Details" is **enabled**


## Performance Optimization

### High-Volume Environments

**Recommended Settings:**
```
Max incidents per fetch: 10000
Fetch Interval: 5 (minutes)
Include Alarm Content: ✓ (enabled)
Include Related Entities: ✓ (enabled)
```

**With Filters:**
```
Status Filter: OPEN only
Severity: HIGH, CRITICAL only
```

This reduces data volume while capturing critical alerts.


### Low-Volume Environments

**Recommended Settings:**
```
Max incidents per fetch: 1000
Fetch Interval: 1 (minutes)
Include Alarm Content: ✓ (enabled)
Include Related Entities: ✓ (enabled)
```

Faster response to new incidents.

## Support

### Official Support
- **SOCRadar XSOAR Support**: [XSOAR@socradar.io](mailto:XSOAR@socradar.io)
- **SOCRadar Support**: [support@socradar.io](mailto:support@socradar.io)
- **Platform**: [platform.socradar.com](https://platform.socradar.com)

### Feature Requests
Submit feature requests through:
1. SOCRadar platform Request
2. XSOAR content repository issues


## Version History

### v4.0.0 (December 2024)
- Initial release of SOCRadar Incidents v4.0
- Multi-status filtering support
- Epoch time precision for zero duplicates
- Reverse pagination implementation
- Dynamic content extraction
- Enhanced deduplication (2-layer)
- New commands: ask-analyst, change-severity
- Parametric company ID display
- Comprehensive debug logging


## License

This integration is provided under the MIT License.

## About SOCRadar

SOCRadar is a leading Extended Threat Intelligence (XTI) platform that helps organizations:
- Monitor and protect their digital assets
- Detect brand abuse and phishing attacks
- Identify stolen credentials and data leaks
- Track dark web activities
- Manage attack surface exposure
- Ensure supply chain security

Learn more: [www.socradar.io](https://www.socradar.io)

---

**Made with ❤️ by the SOCRadar Integration Team and XSOAR teams**
