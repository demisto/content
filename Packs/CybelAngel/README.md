
# CybelAngel XSOAR Integration

## Overview

This integration enables XSOAR users to retrieve, analyze, and manage incidents from CybelAngel, a digital risk protection platform. With CybelAngel’s incident management capabilities, you can detect and respond to data leaks, brand protection issues, and digital asset threats across the open, deep, and dark web.

## Prerequisites

- CybelAngel account with API access.
- XSOAR server version 6.10.0 or higher.

## Configure CybelAngel on XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Click **Add instance** to create and configure a new integration instance.
3. Configure the following settings:
   - **CybelAngel Client ID**: Your CybelAngel API Client ID.
   - **CybelAngel Client Secret**: Your CybelAngel API Client Secret.
   - **CybelAngel Tenant ID**: Tenant ID for your CybelAngel account.
   - **Base URL**: Set to `https://platform.cybelangel.com`.
   - **Fetch incidents**: Enable to allow fetching incidents from CybelAngel.
   - **Incident Fetch Interval**: Define the interval for fetching new incidents.
   - **First Fetch Interval**: The number of days to look back for fetching incidents initially.

4. Click **Test** to validate the connection.

## Commands

The following commands are available once the integration is configured:

### 1. Test Connectivity

**Command:** `!cybelangel-test-module`  
**Description:** Checks the connectivity and credentials of the integration instance.

### 2. Fetch Incidents

**Command:** `!fetch-incidents`  
**Description:** Retrieves incidents based on the configured fetch interval.

### 3. Get Report by ID

**Command:** `!cybelangel-get-report-by-id report_id=<report_id>`  
**Description:** Retrieves details of a specific report based on the report ID.

### 4. Get Report Attachment

**Command:** `!cybelangel-get-report-attachment report_id=<report_id> attachment_id=<attachment_id> file_name=<file_name>`  
**Description:** Fetches an attachment associated with a report by its attachment ID and file name.

### 5. Download Report as PDF

**Command:** `!cybelangel-get-report-pdf report_id=<report_id>`  
**Description:** Downloads a report as a PDF and saves it in the War Room.

### 6. Remediate Report

**Command:** `!cybelangel-remediate report_id=<report_id> email=<email> requester_fullname=<full_name>`  
**Description:** Sends a remediation request for a specific report, specifying the requester’s email and full name.

### 7. Get Comments for Report

**Command:** `!cybelangel-get-comments report_id=<report_id>`  
**Description:** Retrieves all comments associated with a specific report.

### 8. Post Comment on Report

**Command:** `!cybelangel-post-comment report_id=<report_id> comment=<comment>`  
**Description:** Posts a new comment on a report.

### 9. Update Report Status

**Command:** `!cybelangel-update-status report_id=<report_id> status=<status>`  
**Description:** Updates the status of a report. Valid statuses: `open`, `in_progress`, `resolved`, `discarded`.

## Incident Types and Fields

CybelAngel incidents will be automatically fetched and populated in XSOAR. Incident types include:

- **Incident ID**
- **Keywords**
- **Report Content**
- **Report Type**
- **Threat Level**

## Use Cases

- Monitor for data leaks and vulnerabilities in real-time.
- Automate incident handling and incident response.
- Post comments or update the status of CybelAngel incidents directly from XSOAR.

## Support

For any issues or questions, please contact CybelAngel Support:

- Email: [support@cybelangel.com](mailto:support@cybelangel.com)
- Website: [https://cybelangel.com](https://cybelangel.com)
