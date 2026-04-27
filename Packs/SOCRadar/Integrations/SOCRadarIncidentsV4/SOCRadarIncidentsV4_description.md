SOCRadar is a leading Extended Threat Intelligence (XTI) platform that provides comprehensive digital risk protection. This integration enables XSOAR to ingest and manage security incidents from SOCRadar's Incident API v4.

## Key Capabilities

### Incident Types Supported
- **Brand Protection**: Impersonating domains, phishing attacks, brand abuse
- **Cyber Threat Intelligence**: Stolen credentials, data leaks, malware infections
- **Attack Surface Management**: External exposure findings, misconfigurations
- **Dark Web Intelligence**: Compromised credentials, leaked data from dark web sources
- **Supply Chain Security**: Third-party risks and vendor security issues

### Advanced Features
- **Multi-Status Filtering**: Select multiple statuses simultaneously for flexible queries
- **Timestamp-Based Fetching**: Uses last_fetch timestamp to ensure consistent, duplicate-free incident ingestion
- **Dynamic Content Extraction**: Automatically adapts to different alarm types
- **Configurable Enrichment**: Control content and entity inclusion for performance
- **Multi-Tenant Support**: Optional company_id parameter in all commands for MSSP environments

### Incident Management
- Change status with multiple status options including OPEN, INVESTIGATING, RESOLVED, PENDING_INFO, LEGAL_REVIEW, VENDOR_ASSESSMENT, FALSE_POSITIVE, DUPLICATE, PROCESSED_INTERNALLY, MITIGATED, and NOT_APPLICABLE
- Add comments and collaborate on investigations
- Modify assignees and severity levels
- Tag incidents for organization
- Mark false positives and resolved items

## Getting Started

1. Obtain API credentials from SOCRadar platform (**Settings → API & Integrations → API Options**)
2. Copy your **Company API Key** (for Incident API)
3. Note your **Company ID**
4. Configure the integration in XSOAR with these credentials
5. Enable incident fetching and configure filters based on your requirements

## Configuration Tips

- **First Fetch Time**: Set to a reasonable time range like "3 days" or "7 days" for initial setup
- **Max Incidents Per Fetch**: Default is 200 for optimal performance and stability
- **Alarm Type Filtering**: Use alarm_type_ids to include specific alarm types or excluded_alarm_type_ids to exclude certain types
- **Status Filtering**: Filter by OPEN, CLOSED, or ON_HOLD statuses based on your workflow
- **Multi-Tenant Support**: Use company_id parameter in commands for multi-tenant environments

For detailed configuration and command documentation, see the integration README.
