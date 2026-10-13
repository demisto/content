#### Integration Author: Doppel
#### Doppel
Doppel is a Modern Digital Risk Protection Solution, that detects the phishing and brand cyber attacks on the emerging channels. Doppel scans millions of channels online which includes, social media, domains, paid ads, dark web, emerging channels, etc. Doppel can identify the malicious content and cyber threats, and enables their customers to take down the digital risks proactively. The Cortex XSOAR pack for Doppel provides mirrors the alerts created by Doppel as Cortex XSOAR incidents. The pack also contains the commands to perform different operations on Doppel alerts.



### Details for Doppel workflow
1. Name of the instance.
2. Doppel Tenant URL that you can use for calling the [Doppel APIs](https://doppel.readme.io/reference/create_alert). e.g. ,*https://api.doppel.com/*
3. Credentials for the API Version you select (see below).

### Authentication
Select an **API Version**, then fill in only that version's fields. Fields labeled with the other version are ignored.

- **V1 (API Key)**: Fill in the *API Key (V1)* field. *User API Key (V1)* and *Organization Code (V1)* are optional V1 extras.
- **V2 (OAuth 2.0 Client Credentials)**: Fill in the *Client ID (V2)* and *Client Secret (V2)* fields. An organization admin can create these from the **Version 2** tab on the **API Settings** page in Doppel Vision. V2 is recommended: new Doppel API capabilities are added to V2 only.

Reach out to Doppel to get access to the above information.

## Test Configuration

After providing the mandatory details, click **Test** to test the configuration.

---