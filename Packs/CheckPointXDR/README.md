# Check Point XDR Integration

The Check Point XDR (Extended Detection and Response) integration allows you to connect to Check Point's CloudInfra platform to fetch and manage incidents. This integration enables you to retrieve incidents from Check Point XDR, convert them into Cortex XSOAR format, and manage them effectively within your security operations workflows.

## Key Features

- **Authentication**: Authenticate with Check Point CloudInfra using client credentials to retrieve an access token.
- **Incident Fetching**: Fetch incidents from Check Point XDR based on user-defined parameters such as date and limit.
- **Incident Conversion**: Convert incidents from Check Point XDR format to Cortex XSOAR format for seamless integration.
- **Custom Fields**: Map incident details, including severity, status, and insights, to XSOAR custom fields.

## Prerequisites

- A valid Check Point XDR account with API access.
- API credentials (Client ID and Access Key) for authentication.
- Cortex XSOAR version 6.0 or higher.

## Setup Instructions

1. **Configure the Integration**:
   - Navigate to the Integrations page in Cortex XSOAR.
   - Search for "Check Point XDR" and click "Add Instance".
   - Provide the following details:
     - **Base URL**: `https://cloudinfra-gw.portal.checkpoint.com`
     - **Client ID**: Your Check Point XDR client ID.
     - **Access Key**: Your Check Point XDR access key.
     - **First Fetch Time**: The time range for the first fetch (e.g., `3 days`).
     - **Max Fetch**: The maximum number of incidents to fetch per API call.
     - **Verify SSL**: Enable or disable SSL verification.

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