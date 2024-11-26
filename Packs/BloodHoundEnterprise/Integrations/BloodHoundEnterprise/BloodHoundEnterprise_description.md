# BloodHound Enterprise Integration

The **BloodHoundEnterprise** integration allows you to collect, analyze, and manage audit events from BloodHound Enterprise. It provides a streamlined way to monitor and secure your network environment by accessing event data directly from BloodHound Enterprise.

## Integration Configuration

### Configuration Overview

To set up the **BloodHoundEnterprise** integration, configure the following parameters under the **Connect** and **Collect** sections:

### Connect Section

Configure the connection settings to the BloodHound Enterprise server:

- **Server URL** (required):
  - The URL of the BloodHound Enterprise server.
  - Example format: `<your hostname>.bloodhoundenterprise.io`.
  - Make sure to use the correct URL format, without the `https://`.
- **API Token Key** (required):
  - The API token key is used for authentication.
  - You can generate this in your BloodHound Enterprise account settings.
- **API Token ID** (required):
  - The API token ID is required to identify the requests.
  - You can generate this in your BloodHound Enterprise account settings.
- **Trust any certificate (not secure)**:
  - Set to `true` to disable SSL certificate verification.
- **Use system proxy settings**:
  - Enable this option to route traffic through the system's proxy settings.
  - Useful for environments where direct internet access is restricted.

### Collect Section

Specify settings related to event collection:

- **Fetch events**:
  - Enable this option to allow the integration to automatically fetch events periodically.
  - Ensure your server has enough resources if you expect a high volume of events.
- **Maximum number of events per fetch** (advanced):
  - Define the maximum number of audit events to retrieve in a single fetch operation.
  - Default value is `250`.
  - Lower values might reduce load on the server, while higher values can improve performance for larger datasets.
