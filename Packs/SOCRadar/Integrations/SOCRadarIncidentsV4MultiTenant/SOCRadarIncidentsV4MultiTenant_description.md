SOCRadar is a leading Extended Threat Intelligence (XTI) platform that provides comprehensive digital risk protection. This Multi-Tenant integration enables MSPs and MSSPs to ingest and manage security incidents from multiple companies using SOCRadar's Multi-Tenant Incident API.

## Key Capabilities

### Multi-Tenant Features
- **Centralized Management**: Monitor multiple companies from a single integration
- **Automatic Company Tracking**: Each alarm includes company ID and company name
- **Smart Company ID Handling**: Automatically extracts company ID from alarms for actions
- **Company Visibility**: Configurable display of company information in incidents

### Incident Types Supported
- **Brand Protection**: Impersonating domains, phishing attacks, brand abuse
- **Cyber Threat Intelligence**: Stolen credentials, data leaks, malware infections
- **Attack Surface Management**: External exposure findings, misconfigurations
- **Dark Web Intelligence**: Compromised credentials, leaked data from dark web sources
- **Supply Chain Security**: Third-party risks and vendor security issues

### Advanced Features
- **Multi-Status Filtering**: Select multiple statuses simultaneously for flexible queries
- **Epoch Time Precision**: Second-level accuracy eliminates duplicate incidents
- **Reverse Pagination**: Fetches newest incidents first for optimal performance
- **Dynamic Content Extraction**: Automatically adapts to different alarm types
- **Configurable Enrichment**: Control content and entity inclusion for performance
- **Auto Company ID Extraction**: Actions automatically use company ID from alarm data

### Incident Management
- Change status with 11 different status options
- Add comments and collaborate on investigations
- Modify assignees and severity levels
- Tag incidents for organization
- Request analyst assistance directly from SOCRadar
- Mark false positives and resolved items
- **All actions automatically use company ID from alarm** (can be overridden if needed)

## Multi-Tenant Workflow

### Alarm Fetching
1. Integration uses Multi-Tenant ID to fetch alarms from all companies
2. Each alarm includes:
   - `company_id`: Numeric company identifier
   - `company_name`: Company display name
   - All standard alarm fields

### Taking Actions
When performing actions (change status, add comment, etc.):
1. **Default Behavior**: Company ID is automatically extracted from the alarm's data
2. **Override Option**: You can manually specify a different company ID if needed
3. **Seamless Operation**: No need to remember company IDs for each alarm

### Example
```
# Alarm is fetched with company_id: 12345, company_name: "Acme Corp"
# When you mark as resolved, integration automatically uses company_id: 12345
!socradar-mark-resolved alarm_id=98765
# Company ID 12345 is auto-extracted and used

# You can also override if needed:
!socradar-mark-resolved alarm_id=98765 company_id=67890
```

## Getting Started

### Prerequisites
1. SOCRadar Multi-Tenant account with API access
2. Multi-Tenant ID from SOCRadar platform
3. API Key from SOCRadar platform

### Configuration Steps
1. Obtain API credentials from SOCRadar platform (Settings → API & Integrations → API Options)
2. Get your Multi-Tenant ID from your account settings
3. Configure integration instance with your API Key and Multi-Tenant ID
4. Enable incident fetching and configure filters based on your use case
5. Optionally enable/disable company information display in incidents
6. Create automations using the provided commands for incident response workflows

### Key Configuration Options
- **Multi-Tenant ID**: Your multi-tenant identifier (required)
- **API Key**: Your SOCRadar API key (required)
- **Include Company Info**: Show/hide company details in incidents (default: enabled)
- **Status Filters**: OPEN, CLOSED, ON_HOLD (multi-select)
- **Severity Filters**: LOW, MEDIUM, HIGH, CRITICAL
- **Content Inclusion**: Control what data is included in custom fields

## Best Practices for Multi-Tenant Environments

1. **Company Visibility**: Keep "Include Company Info" enabled to easily identify which company each alarm belongs to
2. **Filtering**: Use status and severity filters to manage high volumes across multiple companies
3. **Automation**: Let the integration handle company ID extraction automatically
4. **Override When Needed**: Manually specify company_id only when you need to perform an action for a different company
5. **Incident Naming**: Each incident includes company information in its title for easy identification

For detailed setup instructions and command documentation, see the integration README.
