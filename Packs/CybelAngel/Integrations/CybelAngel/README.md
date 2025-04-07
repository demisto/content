# CybelAngel XSOAR Integration

This integration enables Cortex XSOAR to fetch and manage alerts from the CybelAngel platform, allowing security teams to monitor and respond to digital risk exposure incidents.

## Configuration

### Prerequisites
- CybelAngel API client ID and secret
- CybelAngel tenant ID
- XSOAR platform version 6.0.0 or later

### Setup Instructions
1. Navigate to **Settings > Integrations > Servers & Services**
2. Search for CybelAngel
3. Click **Add instance**
4. Input the following parameters:
   - Client ID
   - Client Secret
   - Tenant ID
   - First fetch interval (optional)

## Commands

### Fetch Incidents
Automatically fetches new CybelAngel alerts as XSOAR incidents.

### cybelangel-get-report-by-id
Retrieves detailed information about a specific report.
```
!cybelangel-get-report-by-id report_id=<report_id>
```

### cybelangel-get-report-attachment
Downloads an attachment from a specified report.
```
!cybelangel-get-report-attachment report_id=<report_id> attachment_id=<attachment_id> filename=<filename>
```

### cybelangel-remediate
Creates a remediation request for a specific report.
```
!cybelangel-remediate report_id=<report_id> email=<email> requester_fullname=<name>
```

### cybelangel-get-comments
Retrieves comments associated with a report.
```
!cybelangel-get-comments report_id=<report_id>
```

### cybelangel-post-comment
Adds a comment to a specified report.
```
!cybelangel-post-comment report_id=<report_id> comment=<comment>
```

### cybelangel-update-status
Updates the status of a report.
```
!cybelangel-update-status report_id=<report_id> status=<status>
```

### cybelangel-get-report-pdf
Downloads the PDF version of a report.
```
!cybelangel-get-report-pdf report_id=<report_id>
```

## Troubleshooting

### Authentication Issues
- Verify API credentials are correct
- Check token expiration (tokens automatically refresh after 1 hour)
- Ensure proper network connectivity to CybelAngel endpoints

### Incident Fetching
- First fetch interval determines initial data pull window
- Subsequent fetches use last run time
- Check logs for any API errors or rate limiting issues

## Known Limitations
- Maximum fetch interval is capped at 500 minutes
- PDF reports may take longer to download for large files
- Attachments must be downloaded individually