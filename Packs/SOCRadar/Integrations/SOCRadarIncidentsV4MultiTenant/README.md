# SOCRadar Incidents v4.0 Multi-Tenant

Fetch and manage security incidents from multiple companies using SOCRadar's Multi-Tenant Incident API. Designed for MSPs, MSSPs, and organizations managing multiple subsidiaries.

![SOCRadar Logo](https://raw.githubusercontent.com/demisto/content/master/Packs/SOCRadar/doc_files/socradar-logo.png)

## Overview

SOCRadar is a digital risk protection platform that provides extended threat intelligence and brand protection capabilities. This Multi-Tenant integration enables XSOAR to ingest security incidents from multiple companies through a single integration instance, including:

- **Brand Protection**: Impersonating domains, phishing attacks, brand abuse
- **Cyber Threat Intelligence**: Stolen credentials, data leaks, malware infections
- **Attack Surface Management**: External exposure findings, misconfigurations
- **Dark Web Intelligence**: Compromised credentials, leaked data from dark web sources
- **Supply Chain Security**: Third-party risks and vendor security issues

---

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

| Feature | Standard v4.0 | Multi-Tenant v4.0 |
|---------|---------------|-------------------|
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
2. Navigate to **Settings → API & Integrations**
3. Go to **API Options** page
4. Copy your **Multi-Tenant API Key**
5. Note your **Multi-Tenant ID** (numeric value)

---

## Configuration

### Integration Settings

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| **Server URL** | Yes | `https://platform.socradar.com/api` | SOCRadar API base URL |
| **API Key** | Yes | - | Your Multi-Tenant API Key from SOCRadar |
| **Multi-Tenant ID** | Yes | - | Your Multi-Tenant ID (integer) |
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
| **Include Company Info** | True | Show company ID and name in incidents |

---

## Installation

### From XSOAR Marketplace

1. Navigate to **Settings → Marketplace**
2. Search for "SOCRadar"
3. Install "SOCRadar Incidents v4.0 Multi-Tenant"
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
2. Search for "SOCRadar Incidents v4 Multi-Tenant"
3. Click **Add instance**

### Step 2: Configure Basic Settings

```
Name: SOCRadar Multi-Tenant Production
Server URL: https://platform.socradar.com/api
API Key: [Your Multi-Tenant API Key]
Multi-Tenant ID: [Your Multi-Tenant ID]
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
  ☑ Include Company Info in Incidents
```

### Step 5: Test Connection

Click **Test** button to verify:
- API connectivity
- Authentication
- Multi-Tenant ID validity
- Access to incidents from multiple companies

## Commands

### Incident Management

All commands support **automatic company ID extraction**. The company ID is automatically pulled from the incident's alarm data. You can override this by providing a `company_id` parameter.

#### `socradar-change-alarm-status`
Change the status of one or more alarms.

**Arguments:**
- `alarm_ids` (Required): Comma-separated alarm IDs (e.g., "12345,67890")
- `status_reason` (Required): New status
  - Options: OPEN, INVESTIGATING, RESOLVED, PENDING_INFO, LEGAL_REVIEW, VENDOR_ASSESSMENT, FALSE_POSITIVE, DUPLICATE, PROCESSED_INTERNALLY, MITIGATED, NOT_APPLICABLE
- `comments` (Optional): Comments explaining the status change
- `company_id` (Optional): Override company ID (auto-extracted if not provided)

**Example:**
```
# Company ID auto-extracted from alarm
!socradar-change-alarm-status alarm_ids="12345" status_reason="RESOLVED" comments="Issue fixed"

# Manual company ID override
!socradar-change-alarm-status alarm_ids="12345" status_reason="RESOLVED" company_id="999"
```

**Outputs:**
- `SOCRadar.Alarm.ID`: Alarm ID
- `SOCRadar.Alarm.Status`: New status
- `SOCRadar.Alarm.CompanyID`: Company ID used

#### `socradar-mark-false-positive`
Mark an alarm as false positive.

**Arguments:**
- `alarm_id` (Required): Alarm ID to mark
- `comments` (Optional): Explanation (default: "False positive")
- `company_id` (Optional): Override company ID (auto-extracted if not provided)

**Example:**
```
!socradar-mark-false-positive alarm_id="12345" comments="Verified safe domain"
```

#### `socradar-mark-resolved`
Mark an alarm as resolved.

**Arguments:**
- `alarm_id` (Required): Alarm ID to mark
- `comments` (Optional): Resolution details (default: "Resolved")
- `company_id` (Optional): Override company ID (auto-extracted if not provided)

**Example:**
```
!socradar-mark-resolved alarm_id="12345" comments="Credentials reset, users notified"
```

#### `socradar-add-comment`
Add a comment to an alarm.

**Arguments:**
- `alarm_id` (Required): Target alarm ID
- `user_email` (Required): Email of user adding comment
- `comment` (Required): Comment text
- `company_id` (Optional): Override company ID (auto-extracted if not provided)

**Example:**
```
!socradar-add-comment alarm_id="12345" user_email="analyst@company.com" comment="Investigating with IT team"
```

#### `socradar-change-assignee`
Change alarm assignee(s).

**Arguments:**
- `alarm_id` (Required): Target alarm ID
- `user_emails` (Required): Comma-separated email addresses
- `company_id` (Optional): Override company ID (auto-extracted if not provided)

**Example:**
```
!socradar-change-assignee alarm_id="12345" user_emails="analyst1@company.com,analyst2@company.com"
```

#### `socradar-add-tag`
Add or remove a tag from an alarm.

**Arguments:**
- `alarm_id` (Required): Target alarm ID
- `tag` (Required): Tag name to add/remove
- `company_id` (Optional): Override company ID (auto-extracted if not provided)

**Example:**
```
!socradar-add-tag alarm_id="12345" tag="priority-high"
```

#### `socradar-ask-analyst`
Request assistance from SOCRadar analyst.

**Arguments:**
- `alarm_id` (Required): Target alarm ID
- `comment` (Required): Question/request for analyst
- `company_id` (Optional): Override company ID (auto-extracted if not provided)

**Example:**
```
!socradar-ask-analyst alarm_id="12345" comment="Need help determining if this is genuine threat"
```

#### `socradar-change-severity`
Change alarm severity level.

**Arguments:**
- `alarm_id` (Required): Target alarm ID
- `severity` (Required): New severity (LOW, MEDIUM, HIGH, CRITICAL)
- `company_id` (Optional): Override company ID (auto-extracted if not provided)

**Example:**
```
!socradar-change-severity alarm_id="12345" severity="HIGH"
```

### Testing

#### `socradar-test-fetch`
Test incident fetching configuration.

**Arguments:**
- `limit` (Optional): Number of incidents to fetch (default: 5)
- `first_fetch` (Optional): Time range to test (default: "3 days")

**Example:**
```
!socradar-test-fetch limit=10 first_fetch="7 days"
```

**Outputs:**
- `SOCRadar.TestFetch.TotalCount`: Number of incidents found
- `SOCRadar.TestFetch.TotalRecords`: Total records available
- `SOCRadar.TestFetch.TotalPages`: Total pages available
- `SOCRadar.TestFetch.SampleIncidents`: Sample incident data
- `SOCRadar.TestFetch.Companies`: List of companies found

---

## Multi-Tenant Workflow Examples

### Example 1: Basic Alarm Resolution
```python
# Incident is fetched with:
# - alarm_id: 98765
# - company_id: 12345
# - company_name: "Acme Corp"

# Mark as resolved - company ID auto-extracted
!socradar-mark-resolved alarm_id="98765" comments="Domain taken down"

# Result: Uses company_id=12345 automatically
```

### Example 2: Working with Multiple Companies
```python
# You have incidents from multiple companies
# Each incident contains its company information

# Filter incidents by company in XSOAR
# Or use incident fields to route to appropriate teams

# Actions work automatically regardless of which company
!socradar-change-alarm-status alarm_ids="11111,22222,33333" status_reason="INVESTIGATING"
# Each alarm uses its own company_id
```

### Example 3: Override Company ID (Advanced)
```python
# Sometimes you need to act on behalf of a different company
# For example, a parent company managing subsidiary alarms

# Alarm is for company 12345, but you want to use company 99999
!socradar-mark-resolved alarm_id="98765" company_id="99999" comments="Handled by parent company"
```

### Example 4: Automation Playbook
```yaml
# Playbook that handles alarms from any company
- task: Extract Alarm Info
  script: |
    incident = demisto.incident()
    alarm_id = incident.get('dbotMirrorId')
    company_id = incident.get('CustomFields', {}).get('socradarcompanyid')
    company_name = incident.get('CustomFields', {}).get('socradarcompanyname')
    
    demisto.setContext('AlarmID', alarm_id)
    demisto.setContext('CompanyID', company_id)
    demisto.setContext('CompanyName', company_name)

- task: Add Investigation Comment
  command: socradar-add-comment
  args:
    alarm_id: ${AlarmID}
    user_email: "soc@company.com"
    comment: "Automated investigation started"
  # Company ID is auto-extracted, no need to specify

- task: Mark as Investigating
  command: socradar-change-alarm-status
  args:
    alarm_ids: ${AlarmID}
    status_reason: "INVESTIGATING"
  # Company ID is auto-extracted
```

---

## Custom Fields

The integration creates the following custom incident fields:

| Field Name | Description | Multi-Tenant Note |
|------------|-------------|-------------------|
| `socradaralarmid` | Alarm ID | Unique across all companies |
| `socradarcompanyid` | Company ID | Identifies which company |
| `socradarcompanyname` | Company Name | Company display name |
| `socradarstatus` | Current status | - |
| `socradarasset` | Affected asset | - |
| `socradaralarmtype` | Main alarm type | - |
| `socradaralarmsubtype` | Alarm sub-type | - |
| `socradarrisklevel` | Risk level | - |
| `socradartags` | Tags | - |
| `socradarentities` | Related entities | - |
| `socradarcontent*` | Dynamic content fields | Varies by alarm type |

---

## Incident Deduplication

The integration implements two-layer deduplication:

1. **Alarm ID Tracking**: Maintains list of last 1000 alarm IDs
2. **Epoch Time Filtering**: Uses second-precision timestamps

This ensures zero duplicate incidents across all companies.

---

## Performance Optimization

### Reverse Pagination
- Fetches newest incidents first (last page → first page)
- Optimal for time-sensitive alerts
- Reduces unnecessary API calls

### Configurable Content Inclusion
- Disable content extraction if not needed
- Reduce memory footprint for high-volume environments
- Speeds up incident creation

### Recommended Settings for High-Volume
```
Max incidents per fetch: 5000
Fetch Interval: 1 minute
Include Alarm Content: False (if not needed)
Include Related Entities: True (usually needed)
Include Company Info: True (essential for multi-tenant)
```

---

## Troubleshooting

### Common Issues

#### Issue: "Invalid Multi-Tenant ID"
**Solution**: Verify your Multi-Tenant ID is:
- A numeric value
- Correct from SOCRadar platform
- Has proper API access enabled

#### Issue: "Authorization Error"
**Solution**: Check that:
- API Key is correct and active
- API Key has multi-tenant permissions
- Key hasn't expired

#### Issue: Company ID Not Auto-Extracted
**Solution**:
- Ensure "Include Company Info" is enabled
- Verify incident has socradarcompanyid in custom fields
- Check incident rawJSON contains company_id field
- If issue persists, manually specify company_id parameter

#### Issue: No Incidents Fetched
**Solution**: 
- Verify Multi-Tenant ID has access to companies with alarms
- Check time range isn't too narrow
- Review status and severity filters
- Use `socradar-test-fetch` to diagnose

#### Issue: Too Many Incidents
**Solution**:
- Adjust status filters (e.g., only OPEN)
- Add severity filters
- Reduce "First fetch time" range
- Increase "Fetch Interval" if appropriate

### Debug Logging

Enable debug logging to troubleshoot:
1. Navigate to **Settings → About → Troubleshooting**
2. Enable debug logging for integration
3. Review logs in **Settings → About → Logs**

Look for lines prefixed with `[SOCRadar V4.0 MT]`

---

## Best Practices

### Multi-Tenant Management
1. **Enable Company Info**: Always keep company information visible in incidents
2. **Use Filters**: Apply status/severity filters to manage high volumes
3. **Route by Company**: Use playbooks to route incidents based on company
4. **Trust Auto-Extraction**: Let the integration handle company IDs automatically
5. **Document Overrides**: If you override company_id, document why in comments

### Security
1. Protect API key as sensitive credential
2. Limit integration user permissions to necessary scopes
3. Review alarm assignments regularly
4. Use XSOAR RBAC to control who can act on which companies' alarms

### Performance
1. Start with small fetch intervals (1 minute)
2. Adjust max_fetch based on alarm volume
3. Use filters to reduce noise
4. Disable content extraction if not needed
5. Monitor integration performance in XSOAR dashboard

---

## Support

### SOCRadar Support
- **Documentation**: [platform.socradar.com/docs](https://platform.socradar.com/docs)
- **Support Portal**: [support.socradar.com](https://support.socradar.com)
- **Email**: support@socradar.com

### XSOAR Support
- **Community**: [Cortex XSOAR Community](https://live.paloaltonetworks.com/t5/cortex-xsoar/ct-p/Cortex_XSOAR)
- **Documentation**: [XSOAR Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsoar)

---

## Additional Resources

- [SOCRadar Platform](https://platform.socradar.com)
- [API Documentation](https://platform.socradar.com/docs/api)
- [Integration GitHub Repository](https://github.com/demisto/content/tree/master/Packs/SOCRadar)

---

## License

This integration is provided as part of the Cortex XSOAR content pack.

---

## Version History

### v4.0 Multi-Tenant (Current)
- Initial multi-tenant release
- Multi-Tenant API endpoint support
- Automatic company ID extraction
- Company name in incidents
- Enhanced company visibility controls
- Smart action handling across companies

### Future Enhancements
- Company-specific filtering in fetch
- Bulk operations across companies
- Company performance dashboards
- Enhanced reporting by company
