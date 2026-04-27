#### How to retrieve a WildFire API key
This API key is used in the *API Key* field in the integration configuration.
1. First, navigate to your [WildFire Account](https://wildfire.paloaltonetworks.com/wildfire/account).
2. Next, log in to your *WildFire* account.
3. Select the *Account* tab from the menu.
4. Lastly, copy the API key.

##### Other Sources of WildFire API keys
- Prisma Cloud Compute
- Prisma Access
- XSOAR TIM

#### WildFire Server URLs
Use the appropriate server URL in the **Server base URL** parameter based on your region or cloud environment:

| Region | Server URL |
| --- | --- |
| Global (default) | https://wildfire.paloaltonetworks.com |
| US Gov Cloud / FedRAMP Moderate | https://pubsec-cloud.wildfire.paloaltonetworks.com |
| US Gov Cloud / FedRAMP High | https://gov-cloud.wildfire.paloaltonetworks.com |
| EU | https://eu.wildfire.paloaltonetworks.com |
| Japan | https://jp.wildfire.paloaltonetworks.com |

For on-premise WildFire appliances, use the appliance IP or hostname with the `/publicapi` path (e.g., `https://192.168.0.1/publicapi`).

Notice: Submitting indicators using the following commands of this integration might make the indicator data publicly available.
- ***wildfire-upload-url***
- ***wildfire-get-url-webartifacts***
See the vendor's documentation for more details.

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/wild-fire-v2)