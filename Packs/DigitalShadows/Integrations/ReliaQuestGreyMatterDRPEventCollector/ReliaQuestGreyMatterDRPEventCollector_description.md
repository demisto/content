Digital Shadows minimizes digital risk by identifying unwanted exposure and protecting against external threats. The award-winning SearchLight solution provides ongoing monitoring of a customer's unique assets and exposure across the open, deep, and dark web. This enables clients to detect data loss, brand impersonation, infrastructure risks, cyber threats, and much more.

This integration fetches event items which can be either incident/alerts, for more information, see [here](https://portal-digitalshadows.com/learn/searchlight-api/key-words/triage).

## ReliaQuest GreyMatter DRP EventCollector Authentication
Requests to all operation endpoints require HTTP Basic authentication, using dedicated (high entropy) API credentials. These normally consist of a six character key, and a 32 character 'secret'. Note that you will not be able to use your normal email/password login details with the HTTP Basic authentication mechanism.

Contact your Digital Shadows representative to obtain API credentials.

To authenticate the integration, you must have a username, password and account ID. To get the account ID, see [here](https://portal-digitalshadows.com/api/stored-objects/portal/searchlight-api-docs/SearchLightAPI_APIKey_AccountId2.pdf).

## Limitations
Increasing the Maximum number of events per fetch parameter to high numbers can cause rate-limits, however The integration will recover from those rate-limits automatically. For more information about rate-limits, see [here](https://portal-digitalshadows.com/learn/searchlight-api/overview/rate-limiting).