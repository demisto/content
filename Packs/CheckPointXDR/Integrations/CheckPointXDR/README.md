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

### fetch-incidents

***
Fetches incidents from Check Point XDR and converts them into Cortex XSOAR format.

#### Base Command

`fetch-incidents`

#### Input

This command uses the parameters from the integration instance configuration:

- **First fetch time**
- **Max fetch**

#### Context Output

| **Path** | **Type** | **Description** |
|---------|----------|-----------------|
| incident.name | string | Incident name |
| incident.type | string | Incident type |
| incident.severity | number | Incident severity |
| incident.occurred | date | Incident timestamp |
| incident.xdrstatus | string | Incident status |
| incident.xdrid | string | Unique ID of the incident |
| incident.insights | string | Associated insights |
| incident.assets | string | Affected assets |
| incident.mitre | string | MITRE TTPs |

#### Human Readable Output

> ✅ Successfully fetched X incidents.

---

### get-mapping-fields

***
Returns the fields available for mapping incoming incidents to Cortex XSOAR fields.

#### Base Command

`get-mapping-fields`

#### Input

None

#### Context Output

The fields available in XSOAR for incident mapping.

#### Command Example

`!get-mapping-fields`

#### Human Readable Output

> Displays the supported incident fields for mapping from Check Point XDR.

---

### update-remote-system

***
Sends updates from Cortex XSOAR to the corresponding incident in Check Point XDR, such as status changes or ownership updates.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|------------------|--------------|
| remoteId | The ID of the incident in Check Point XDR. | True |
| data | The fields to update (status, owner, etc). | True |
| entries | Entries (comments, notes) to be pushed. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

`!update-remote-system`

#### Human Readable Output

> ✅ Remote incident successfully updated.

---

## Incident Fields

| **Field** | **Description** |
|-----------|-----------------|
| xdrid | Unique identifier of the incident |
| xdrstatus | Current status (e.g. New, In Progress, Resolved) |
| severity | Incident severity mapped to XSOAR levels |
| summary | Short summary of the incident |
| insights | Detailed related alerts and context |
| assets | Affected hosts, users, and services |
| mitre | Associated MITRE ATT&CK tactics and techniques |

---

## Example Use Case

1. Authenticate with Check Point XDR using your client credentials.
2. Fetch incidents from Check Point XDR based on the specified date and limit.
3. Convert the incidents into Cortex XSOAR format, including custom fields for insights, alerts, and assets.
4. Manage and respond to incidents directly within Cortex XSOAR.

## Troubleshooting

- **Authentication Errors**: Ensure the Client ID and Access Key are correct and have the necessary permissions.
- **No Incidents Fetched**:

1. Verify the date range parameter is long enough (so there are incidents to fetch).
2. Verify the limit parameter in the integration configuration is higher then 0.
3. Verify your client Id and Access key are correct - copy them from the XDR portal under your settings.
4. Verify the Fetch Incidents checkbox is cheked.

- **SSL Errors**: If SSL verification is enabled, ensure the base URL uses a valid SSL certificate.

## Additional Resources

- [Check Point XDR Documentation](https://www.checkpoint.com/products/extended-detection-response-xdr/)
- [Cortex XSOAR Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsoar)

## Support

For support, please contact Check Point or your system administrator.
