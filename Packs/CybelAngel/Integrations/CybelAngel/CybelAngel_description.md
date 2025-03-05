# CybelAngel Integration for Cortex XSOAR

This integration connects Cortex XSOAR with CybelAngel's API to manage and fetch alerts. This document details the setup and configuration using abstracted methods without a direct client class.

## Prerequisites

Ensure you have the following CybelAngel account information:
- **Client ID** 
- **Client Secret** 
- **Tenant ID**

## Configuration Parameters

- **Client ID**: Provided by CybelAngel.
- **Client Secret**: Provided by CybelAngel.
- **Tenant ID**: Required for posting comments on reports.

### Fetch Interval Parameters

- **First Fetch Interval**: Defines how many days of historical data to fetch on the initial connection (in days).
- **Incident Fetch Interval**: Sets the time between regular fetches (in minutes or specified time format).

## Integration Steps

1. **Set Up Authentication**
   - Authentication is based on OAuth 2.0, using Client ID and Client Secret.
   - A token is fetched initially and refreshed based on the token's validity. 

2. **Fetch Incidents Setup**
   - The `first_fetch_interval` parameter is used only on the first run to fetch historical alerts.
   - Subsequent fetches occur based on the `incident_fetch_interval` time.

3. **CybelAngel API Endpoints Used**
   - **Token Fetch**: `/oauth/token`
   - **Reports Fetch**: `/api/v2/reports`
   - **Single Report by ID**: `/api/v2/reports/{report_id}`
   - **Report Attachments**: `/api/v1/reports/{report_id}/attachments/{attachment_id}`
   - **Remediation Request**: `/api/v1/reports/remediation-request`
   - **Comments**: `/api/v1/reports/{report_id}/comments`
   - **Status Update**: `/api/v1/reports/{report_id}/status`
   - **PDF Report**: `/api/v1/reports/{report_id}/pdf`

## Commands Implemented

### Fetch Incidents
Fetches alerts from CybelAngel based on the defined interval. On the first run, it retrieves alerts as per the `first_fetch_interval`.

### Get Report by ID
Retrieves a specific report using the report ID.

### Get Report Attachment
Fetches a specific attachment for a report.

### Remediate
Creates a remediation request for a given report ID.

### Get Comments
Fetches comments associated with a report.

### Post Comment
Posts a comment on a specified report.

### Update Status
Updates the status of a report.

### Get Report PDF
Downloads a PDF version of a report.

## Support and Contact

For further assistance, please contact CybelAngel:
- **Email**: [support@cybelangel.com](mailto:support@cybelangel.com)
- **Support URL**: [CybelAngel Support](https://support.cybelangel.com)

## Example Code Structure (Abstracted)

Refer to the CybelAngel developer documentation for specific API details and response structures.

```python
# Basic example function to fetch a token
def fetch_token(client_id, client_secret):
    # Token fetching logic using client_id and client_secret
    pass

# Example function to fetch reports based on interval
def fetch_reports(interval_minutes):
    # Implement the fetching logic here
    pass