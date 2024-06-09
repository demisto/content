ReliaQuest GreyMatter DRP Event Collector minimizes digital risk by identifying unwanted exposure and protecting against external threats. The award-winning SearchLight solution provides ongoing monitoring of a customer's unique assets and exposure across the open, deep, and dark web. This enables clients to detect data loss, brand impersonation, infrastructure risks, cyber threats, and much more.

This integration fetches event items which can be either incident/alerts, for more information refer [here](https://portal-digitalshadows.com/learn/searchlight-api/key-words/triage)

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure ReliaQuest GreyMatter DRP Event Collector On XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for Relia Quest GreyMatter DRP Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                      | **Description**                                                                      | **Required** |
    |------------------------------------|--------------------------------------------------------------------------------------|--------------|
    | Server URL                         | URL for the Relia Quest API instance.                                                | True         |
    | Account ID                         | The account ID for the Reila Quest instance.                                         | True         |
    | Maximum number of events per fetch | The maximum number of events to fetch every time fetch is executed. Default is 1000. | True         |
    | Trust any certificate (not secure) |                                                                                      | False        |
    | Use system proxy settings          |                                                                                      | False        |
    | Username                           | The username to authenticate Relia Quest Event Collector.                            | False        |
    | Password                           | The password to authenticate Relia Quest Event Collector                             | False        |
5. Click **Test** to validate the URLs, token, and connection.


## ReliaQuest GreyMatter DRP EventCollector Authentication
Requests to all operation endpoints require HTTP Basic authentication, using dedicated (high entropy) API credentials. These normally consist of a six character key, and a 32 character 'secret'. Note that you will not be able to use your normal email/password login details with the HTTP Basic authentication mechanism.

Contact your Digital Shadows representative to obtain API credentials.

To authenticate the integration, you must have a username, password and account ID. To get the account ID, see [here](https://portal-digitalshadows.com/api/stored-objects/portal/searchlight-api-docs/SearchLightAPI_APIKey_AccountId2.pdf).
## Limitations
Increasing the Maximum number of events per fetch parameter to high numbers can cause rate-limits, however The integration will recover from those rate-limits automatically. For more information about rate-limits, see [here](https://portal-digitalshadows.com/learn/searchlight-api/overview/rate-limiting).