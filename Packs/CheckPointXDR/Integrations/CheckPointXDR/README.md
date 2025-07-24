# Check Point XDR Integration

The Check Point XDR (Extended Detection and Response) integration allows you to connect to Check Point's CloudInfra platform to fetch and manage incidents. This integration enables you to retrieve incidents from Check Point XDR, convert them into Cortex XSOAR format, and manage them effectively within your security operations workflows.

## Key Features

- **Authentication**: Secure OAuth2-based authentication using Client ID and Access Key.
- **Incident Fetching**: Retrieve incidents from Check Point XDR using flexible parameters such as timestamp and limit.
- **Data Mapping**: Automatically map Check Point fields such as severity, status, summary, and insights into XSOAR incident fields.
- **Custom Fields Support**: Includes mapping for MITRE ATT&CK techniques, assets, and alerts.
- **Pagination Support**: Automatically fetches additional pages of incidents if the result size equals the `max_fetch` parameter.
- **Insights & Enrichment**: Include related context such as associated users, endpoints, and threat intelligence.


## Prerequisites

- A valid Check Point XDR account with API access enabled.
- API credentials:
  - **Client ID**
  - **Access Key**
- Cortex XSOAR version **6.10.0** or higher.

## Use Cases

- Ingest Check Point XDR alerts and incidents into XSOAR for automated playbook-driven response.
- Correlate assets, users, and threats across your SOC toolset.
- Perform enrichment using insights and threat classifications included in the XDR data.
- Monitor status and severity changes and trigger escalation or remediation workflows.

## Setup Instructions
1.
    1. Navigate to **Settings** → **Integrations** → **Servers & Services**.
    2. Search for **Check Point XDR** and click **Add instance**.
    3. Configure the following parameters:

    | **Parameter**         | **Description**                                                                                |
    |-----------------------|-----------------------------------------------------------------------------------------------|
    | Base URL              | Default: `https://cloudinfra-gw.portal.checkpoint.com`                                        |
    | Client ID             | Your Check Point XDR API Client ID                                                            |
    | Access Key            | Your Check Point XDR API Access Key                                                           |
    | First fetch time      | Format: `3 days`, `2 hours`, etc. Determines the starting point of the initial fetch.         |
    | Max fetch             | Maximum number of incidents to fetch per API call (default recommended: 50-100)              |
    | Fetch incidents       | Enable to allow scheduled fetching of incidents                                               |
    | Trust any certificate | Disable SSL validation (not recommended for production environments)                          |
    | Use system proxy      | Use the system proxy defined in Cortex XSOAR settings     

2. **Test the Integration**:
   - Click the "Test" button to verify the connection and configuration.

3. **Fetch Incidents**:
   - Enable the "Fetches incidents" option to allow the integration to periodically fetch incidents from Check Point XDR.

## Commands

The integration provides the following commands:

### 1. `test-module`

- **Description**: Tests the connection to Check Point XDR.
- **Usage**: Run this command to ensure the integration is configured correctly.

### 2. `fetch-incidents`

- **Description**: Fetches incidents from Check Point XDR and converts them into Cortex XSOAR format.
- **Usage**: This command is executed automatically when the "Fetches incidents" option is enabled.

### 3. `get-mapping-fields`

- **Description**: Returns the fields available for mapping incoming incidents to Cortex XSOAR fields.
- **Usage**: Used internally when setting up field mapping under Settings → Integrations → Field Mapping (incoming)

### 4. `update-remote-system`

- **Description**: Sends updates from Cortex XSOAR to the corresponding incident in Check Point XDR, such as status changes or ownership updates.
- **Usage**: Executed automatically when bidirectional mirroring is enabled and a change is made locally.


## Incident Fields

The following fields are mapped from Check Point XDR incidents to Cortex XSOAR:

- **Incident ID**: The unique identifier of the incident.
- **Severity**: The severity level of the incident (mapped to XSOAR severity levels).
- **Status**: The current status of the incident (e.g., new, in-progress).
- **Summary**: A brief description of the incident.
- **Insights**: Detailed insights and alerts associated with the incident.
- **Assets**: Affected hosts and users.
- **MITRE Tactics and Techniques**: Associated MITRE ATT&CK tactics and techniques.

## Example Use Case

1. Authenticate with Check Point XDR using your client credentials.
2. Fetch incidents from Check Point XDR based on the specified date and limit.
3. Convert the incidents into Cortex XSOAR format, including custom fields for insights, alerts, and assets.
4. Manage and respond to incidents directly within Cortex XSOAR.

## Troubleshooting

- **Authentication Errors**: Ensure the Client ID and Access Key are correct and have the necessary permissions.
- **No Incidents Fetched**: Verify the date range and limit parameters in the integration configuration.
- **SSL Errors**: If SSL verification is enabled, ensure the base URL uses a valid SSL certificate.

## Additional Resources

- [Check Point XDR Documentation](https://www.checkpoint.com/products/extended-detection-response-xdr/)
- [Cortex XSOAR Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsoar)

## Support

For support, please contact Check Point or your system administrator.