# BloodHound Enterprise Integration

Use the **BloodHoundEnterprise** integration to collect and analyze audit events from BloodHound Enterprise.

## Integration Configuration

To set up the **BloodHoundEnterprise** integration, configure the following parameters:

### Connect Section
- **Server URL** (required): The URL of the BloodHound Enterprise server. For example, `<your hostname>.bloodhoundenterprise.io`.
- **API Token Key** (required): The API token key from BloodHound Enterprise for authenticating requests.
- **API Token ID** (required): The API token ID from BloodHound Enterprise for authenticating requests.
- **Trust any certificate (not secure)**: Set this to true to ignore SSL certificate verification (not recommended for production environments).
- **Use system proxy settings**: Enable this to use the proxy settings defined in the system.

### Collect Section
- **Fetch events**: Enable this option to fetch events automatically.
- **Maximum number of events per fetch** (advanced): The maximum number of audit events to retrieve per fetch. Default is `250`.