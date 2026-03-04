## Dataminr Pulse - ReGenAI Help

To use the integration, Client ID and Client Secret will be required, which are associated with a single user account in the Dataminr Web Application. This account must be initialized and configured via the Web Application. At least one valid Watchlist must be configured on the account before using integration.

### Instance Configuration

1. Configure an integration instance with valid Client ID and Client Secret.
2. Click **Test** to validate the connection.
3. To fetch Dataminr Pulse Alerts as an incidents in XSOAR, select the option `Fetches incidents` and follow the table to update configuration parameters.

| **Parameter** | **Description** |
| --- | --- |
| Classifier | Select "N/A"|
| Incident type | Select "Dataminr Pulse ReGenAI Alert"|
| Mapper (incoming) | Select "Dataminr Pulse - Incoming Mapper"|
| Client ID | The Client ID required to authenticate to the service.|
| Client Secret | The Client Secret required to authenticate to the service.|
| Watchlist Names | Provide the watchlist names from which to fetch the alerts. If not provided, alerts will be fetched from all available watchlists on the platform. |
| Query | Terms to search within Dataminr Alerts. |
| Alert Type | Filters the incoming alerts with the provided alert type. Default All. |
| Max Fetch | The maximum number of alerts to fetch each time. If the value is greater than 100, it will be considered as 100. The maximum is 100. |
| Source Reliability | Reliability of the source providing the intelligence data. |
| Create relationships |  Create relationships between indicators as part of enrichment. |
| Trust any certificate (not secure) | Indicates whether to allow connections without verifying the SSL certificate's validity. |
| Use system proxy settings | Indicates whether to use XSOAR's system proxy settings to connect to the API. |
| Incidents Fetch Interval | The incident fetch interval. |

#### (Optional) Set up Google Maps in Cortex XSOAR to Display Alert Locations in the Incident Layout

1. In Google Cloud Platform, do the following:

    - Create a [Google Cloud Project](https://developers.google.com/maps/documentation/javascript/cloud-setup).
    - Enable APIs and Services (**API & Services>Dashboard> ENABLE APIS AND SERVICES**).
    - Enable **Maps JavaScript API**.
    - Create the [Maps JavaScript API key](https://developers.google.com/maps/documentation/javascript/get-api-key#creating-api-keys) ( **Credentials> CREATE CREDENTIALS>API key**).
    - Copy the Maps JavaScript API key.

2. Add the Maps JavaScript API key to Cortex XSOAR.

    - For XSOAR 6: Select **Settings > ABOUT > Troubleshooting > Add Server Configuration**.
    For XSOAR 8: Select **Settings & Info > Settings > Server Settings > Add Server Configuration**.
    - Add the following key and value:
      | Key | Value |
      | --- | --- |
      | `ui.google.api.key` | `<Maps JavaScript API key>` |
    - Click **Save**.

#### Support

- If you have questions or concerns about the content you’re receiving, please reach out for support at [https://www.dataminr.com/dataminr-support#support](https://www.dataminr.com/dataminr-support#support), OR email your Dataminr Customer Success Manager.

#### Contact

- To learn more and reach out to our Sales team, contact us [here](https://www.dataminr.com/contactus-palo-alto?utm_source=Palo%20Alto&utm_medium=partner&utm_sector=corporate-risk&utm_segment=all&utm_region=global&utm_campaign=Partner-Marketing_Marketplace_Palo-Alto-Networks_Global_2023&integration_interest=Palo%20Alto%20Networks%20/%20Cortex%20XSOAR).
