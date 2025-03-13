### Proofpoint Isolation
Proofpoint Isolation is a fully managed cloud-based solution that provides secure web browsing by isolating user sessions, protecting against threats like malware, phishing, and data breaches.

### Proofpoint Isolation Event Collector:
The Proofpoint Isolation Event Collector fetches Browser and Email Isolation events,
providing details such as user activity, URLs accessed, classifications, and dispositions to
enhance security monitoring and incident response.

### Supported Timestamp Formats:
Timestamp is extracted from the **date** field with the following format - yyyy-mm-ddTHH:MM:SS.SSS

### Collect Events from Proofpoint Isolation (XSIAM)

**On Proofpoint Isolation side:**
1. Navigate to **Product Settings** >  **Reporting API**.
2. Copy the **Reporting API Key**.

**On Cortex XSIAM side:**
1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. Type **Proofpoint Isolation** on the search bar.
3. Select the **Proofpoint Isolation** integration.
4. Click **Connect**.
5. Set the following values:
   - Name as `Proofpoint Isolation`
   - API Key - Paste the **Reporting API Key** you copied from the **Proofpoint Isolation** UI.
6. Click **Connect**.