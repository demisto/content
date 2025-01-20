### Proofpoint Isolation
This pack includes integration and modeling rules for Proofpoint Isolation logs.

### Supported Timestamp Formats:
Timestamp is extracted from the **date** field with the following format - yyyy-mm-ddTHH:MM:SS.SSS

### Collect Events from Proofpoint Isolation (XSIAM)

**On Proofpoint Isolation side:**
1. Navigate to **Product Settings** >  **Reporting API**.
2. Copy the **Reporting API Key**.

**On XSIAM side:**
1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. Type **Proofpoint Isolation** on the search bar.
3. Select the **Proofpoint Isolation** integration.
4. Click **Connect**.
5. Set the following values:
   - Name as `Proofpoint Isolation`
   - API Key - paste the **Reporting API Key** we copied from **Proofpoint Isolation** UI.
6. Click **Connect**.