### Get a Threat Command API Key

* Create an account in Threat Command.
* Connect your account to Threat Command.
* Generate your API account ID & API key (Settings -> Subscription -> Generate API Key).

### MSSP users:

Insert your sub-account ID in order to perform MSSP actions.

### Instance Configuration:

1. Configure an integration instance with a valid Server URL, Account ID and API key.
2. Click Test to validate the connection.
3. To fetch Threat Command Alerts as XSOAR Incidents, select the option Fetches incidents and follow the table to update configuration parameters.

| **Parameter**                       | **Description**                                                                                                                                       |
|-------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Classifier                          | Select "N/A".                                                                                                                                         |
| Incident type                       | Select "Rapid7 ThreatCommand Alert".                                                                                                                  |
| Mapper (incoming)                   | Select "Rapid7 ThreatCommand - Incoming Mapper".                                                                                                      |
| Server URL                          | URL of the Rapid7 platform.                                                                                                                           |
| Account ID                          | Account ID of the Rapid7 platform.                                                                                                                    |
| API key                             | API key of the Rapid7 platform.                                                                                                                       |
| Source Reliability                  | Reliability of the source providing the intelligence data.                                                                                            |
| First fetch timestamp.              | Timestamp in ISO format or &lt;number&gt; &lt;time unit&gt;, e.g., 2023-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. The default is "1 day". |
| Maximum incidents per fetch         | The maximum number of alerts to fetch each time. The default is 50. If the value is greater than 200, it will be considered as 200.                   |
| Alert types to fetch as incidents   | Alert types to fetch as incidents. The possible values are AttackIndication, DataLeakage, Phishing, BrandSecurity, ExploitableData, and vip.          |
| Network types to fetch as incidents | Network types to fetch as incidents. The possible values are Clear Web and Dark Web.                                                                  |
| Minimum Alert Severity Level        | Alerts with the minimum level of severity to fetch. The possible values are High, Medium, and Low.                                                    |
| Source types to filter alerts by    | Source types to filter alerts by. The possible values are ApplicationStores, BlackMarkets, HackingForums, SocialMedia, PasteSites, and Others.        |
| Fetch closed alerts                 | Boolean value indicating to fetch closed alerts from Rapid7 platform.                                                                                 |
| Include CSV files of alerts         | Boolean value indicating to include CSV files of alerts.                                                                                              |
| Include attachments of alerts       | Boolean value indicating to include attachments of alerts. MSSP accounts must provide a sub-account ID to perform this action.                        |
| Sub-account ID (for MSSP accounts). | Sub-account ID for MSSP accounts.                                                                                                                     |
| Use system proxy settings           | Indicates whether to use XSOAR's system proxy settings to connect to the API.                                                                         |
| Trust any certificate (not secure)  | Indicates whether to allow connections without verifying the SSL certificate's validity.                                                              |
| Incidents Fetch Interval            | The incident fetch interval. The default is "1 minute".                                                                                               |
