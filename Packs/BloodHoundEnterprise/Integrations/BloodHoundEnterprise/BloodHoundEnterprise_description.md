# BloodHound Enterprise Event Collector

Use this integration to fetch audit logs from **BloodHound** as events in Cortex XSIAM.

## Integration Configuration

### Configuration Overview

To set up the **BloodHoundEnterprise** integration, configure the following parameters under the **Connect** and **Collect** sections:

### Connect Section

Configure the connection settings to the BloodHound Enterprise server:

- **Server URL** (required):
  - The URL of the BloodHound Enterprise server.
- **API Token Key** (required):
  - The API token key is used for authentication.
- **API Token ID** (required):
  - The API token ID is required to identify the requests.
- You can generate a personal API Key/ID pair in your BloodHound Enterprise account settings. For more information click [here](https://support.bloodhoundenterprise.io/hc/en-us/articles/11311053342619-Working-with-the-BloodHound-API#h_01HQBFQX7EE8SZHPPFF0KMQ6NG)

### Collect Section

Specify settings related to event collection:

- **Fetch events**:
  - Enable this option to allow the integration to automatically fetch events periodically.
- **Maximum number of events per fetch** (advanced):
  - Define the maximum number of audit events to retrieve in a single fetch operation.
