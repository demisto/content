## Infoblox Threat Defense with DDI Help

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
3. To fetch Infoblox SOC insights as an incidents in XSOAR, select the option `Fetches incidents` and follow the table to update configuration parameters.

| **Parameter**                      | **Description**                                                                                                                         |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Classifier                         | Select "N/A"                                                                                                                            |
| Incident type                      | Select "Infoblox Cloud Insight".                                                                                                        |
| Mapper (incoming)                  | Select "Infoblox Cloud - Incoming Mapper"                                                                                               |
| Service API Key                    | The Service API Key required to connect to Infoblox Cloud.                                                                              |
| Source Reliability                 | The reliability of the source providing the intelligence data.                                                                          |
| Insight Status                     | Retrieve the insights as specified status.                                                                                              |
| Insight Threat Type                | Retrieve the insights as specified threat type.                                                                                         |
| Insight Priority Level             | Retrieve the insights as specified priority level.                                                                                      |
| Max Fetch                          | The maximum number of incidents to fetch each time. If the value is greater than 200, it will be considered as 200. The maximum is 200. |
| Create relationships               | Creates relationships between indicators as part of Enrichment.                                                                         |
| Trust any certificate (not secure) | Indicates whether to allow connections without verifying the SSL certificate's validity.                                                |
| Use system proxy settings          | Indicates whether to use XSOAR's system proxy settings to connect to the API.                                                           |
| Incidents Fetch Interval           | The incident fetch interval.                                                                                                            |

### Support

- For technical support or troubleshooting, please contact Infoblox Support at [https://www.infoblox.com/support/](https://www.infoblox.com/support/)
- For documentation and resources, visit [https://docs.infoblox.com/](https://docs.infoblox.com/)

### Contact

- For more information about Infoblox Threat Defense with DDI, visit [https://info.infoblox.com/contact-form/](https://info.infoblox.com/contact-form/)

### Notice

- Submitting indicators using the **bloxone-td-lookalike-domain-list** command of this integration might make the indicator data publicly available. See the vendor’s documentation for more details.
