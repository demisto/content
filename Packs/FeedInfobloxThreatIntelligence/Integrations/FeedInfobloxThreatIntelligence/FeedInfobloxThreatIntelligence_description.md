# Infoblox Threat Intelligence Feed Help

### Creating Service API Key

You can create multiple service API keys that are associated with respective service API keys for specific purposes. You must have the required permission to create service API keys. For information, see [Configuring Service API Key](https://docs.infoblox.com/space/BloxOneCloud/35430173).

To create a service API key, complete the following:

1. From the SSO portal, click **User Access** from the left navigation panel and then click the **Service API Keys** tab.

2. On the Service API Keys tab, click **Create**.

3. In the Create Service API Keys dialog, complete the following:

  - **Name**: Enter the name of the user API key. Use a name that can identify the purpose of the key.

  - **Service User**: Enter the name of the service users or choose one from the drop-down list. You can associate up to 10 service API keys per service user.

  - **Expires at**: Click the calendar icon to select a date and time when the service API key should expire. This date determines the duration of key validity.

4. Click **Save & Close** to save the configuration. The new service API key is generated.

5. In the API Access Key Generated dialog, click **Copy** to copy the key and save it in a place where you can locate the key in the future.

### Instance Configuration

1. Configure an integration instance with a valid Service API Key.
2. Click **Test** to validate the connection.
3. To fetch Infoblox threat intelligence indicators, select the option `Fetches indicators` and follow the table to update configuration parameters.

| **Parameter**                      | **Description**                                                                                                                                                                                                                     |
|------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Classifier                         | Select "N/A"                                                                                                                                                                                                                        |
| Mapper (incoming)                  | Select "N/A"                                                                                                                                                                                                                        |
| Service API Key                    | The Service API Key required to connect to Infoblox TIDE API for authentication.                                                                                                                                                    |
| Indicator Types                    | Select the types of indicators to retrieve: IP, HOST, URL, EMAIL, HASH. Default: All types selected.                                                                                                                                |
| First Fetch Time                   | The date or relative timestamp from where to start fetching indicators. Supports formats like "2 days", "yyyy-mm-dd", "yyyy-mm-ddTHH:MM:SSZ". Note: The maximum allowed relative time is 4 hours or 240 minutes. Default is 1 hour. |
| Max Indicators Per Fetch           | The maximum number of indicators to fetch in each run. Maximum allowed value is 50000. Default: 1000.                                                                                                                               |
| DGA Threat                         | Filter indicators having threats originated from dynamically generated algorithms. Options: Yes/No.                                                                                                                                 |
| Threat Classes                     | Filter indicators by threat classes such as DGA, Malicious, Phishing, MalwareC2, Suspicious, etc.                                                                                                                                   |
| Data Providers                     | Filter indicators by data provider profiles: IID, AISCOMM.                                                                                                                                                                          |
| Indicator Reputation               | Set the reputation for indicators from this feed: Unknown, Benign, Suspicious, Malicious. Default: Suspicious.                                                                                                                      |
| Source Reliability                 | The reliability of the source providing the intelligence data. Default: B - Usually reliable.                                                                                                                                       |
| Traffic Light Protocol Color       | The TLP designation to apply to indicators: RED, AMBER, GREEN, WHITE. Default: AMBER.                                                                                                                                               |
| Tags                               | Tags to apply to indicators from this feed. Supports CSV values.                                                                                                                                                                    |
| Bypass exclusion list              | When selected, the exclusion list is ignored for indicators from this feed.                                                                                                                                                         |
| Indicator Expiration Method        | Policy for indicator expiration: Indicator Type, Time Interval, Never Expire, When removed from the feed. Default: Indicator Type.                                                                                                  |
| Feed Fetch Interval                | Interval in minutes between indicator fetch operations. Note: The maximum allowed interval is 4 hours or 240 minutes. Default is 60 minutes.                                                                                        |
| Trust any certificate (not secure) | Indicates whether to allow connections without verifying the SSL certificate's validity.                                                                                                                                            |
| Use system proxy settings          | Indicates whether to use XSOAR's system proxy settings to connect to the API.                                                                                                                                                       |

### Support

- For technical support or troubleshooting, please contact Infoblox Support at [https://www.infoblox.com/support/](https://www.infoblox.com/support/)
- For documentation and resources, visit [https://docs.infoblox.com/](https://docs.infoblox.com/)

### Contact

- For more information about Infoblox Threat Intelligence, visit [https://info.infoblox.com/contact-form/](https://info.infoblox.com/contact-form/)
