Digital Shadows minimizes digital risk by identifying unwanted exposure and protecting against external threats. The award-winning SearchLight solution provides ongoing monitoring of a customer's unique assets and exposure across the open, deep, and dark web. This enables clients to detect data loss, brand impersonation, infrastructure risks, cyber threats, and much more.

This integration fetches event items which can be either incident/alerts, for more information refer [here](https://portal-digitalshadows.com/learn/searchlight-api/key-words/triage)

## Configure Relia Quest GreyMatter DRP Event Collector On XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for Relia Quest GreyMatter DRP Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                      | **Description**                                                                                                                                                    | **Required** |
    |------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
    | Server URL                         | URL for the Relia Quest API instance.                                                                                                                              | True |
    | Account ID                         | The account ID for the Reila Quest instance.                                                                                                                       | True |
    | Maximum number of events per fetch | The maximum number of events to fetch every time fetch is being executed. Default is 200.                                                                          | True |
    | Trust any certificate (not secure) | By default, SSL verification is enabled. If selected, the connection isn’t secure and all requests return an SSL error because the certificate cannot be verified. | False |
    | Use system proxy settings          | Uses the system proxy server to communicate with the  integration. If not selected, the integration will not use the system proxy server.                          | False |
    | Username                           | The username to authenticate Relia Quest Event Collector.                                                                                                          | False |
    | Password                           | The password to autheticate Relia Quest Event Collector                                                                                                            | False |
5. Click **Test** to validate the URLs, token, and connection.


## Relia quest GreyMatter DRP EventCollector Authentication
Requests to all operation endpoints require HTTP Basic authentication, using dedicated (high entropy) API credentials. These normally consist of a six character key, and a 32 character 'secret'. Note that you will not be able to use your normal email/password login details with the HTTP Basic authentication mechanism.

Please contact your Digital Shadows representative to obtain API credentials.

To authenticate the integration, it is required to have username, password and account-id, to get the account-id refer to [here](https://portal-digitalshadows.com/api/stored-objects/portal/searchlight-api-docs/SearchLightAPI_APIKey_AccountId2.pdf)

## Limitations
* The Relia Quest product can return rate-limits when doing too many http-requests, increasing the **Maximum number of events per fetch** parameter to high numbers can cause rate-limits. The integration knows to recover from those rate-limits automatically in some cases, but not in all of them. For more information about rate-limits refer [here](https://portal-digitalshadows.com/learn/searchlight-api/overview/rate-limiting)
