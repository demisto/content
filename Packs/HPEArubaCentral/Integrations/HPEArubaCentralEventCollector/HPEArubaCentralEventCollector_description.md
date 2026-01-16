## HPE Aruba Central Help

### How to generate Client ID and Secret

In order for the collector to access the Aruba Central API, it must first be added as an application in the Aruba Central API gateway. Doing so will generate a unique pair of client ID and secret to be used for authentication. 

1. Go to the Aruba Central portal and navigate to **Accounts Home** > **Global Settings** > **API Gateway**.

   - Admin users: Navigate to **System Apps & Tokens**.
   - Non-admin users: Navigate to **My Apps & Tokens**.

2. Click **+ Add Apps & Tokens**.
3. Fill in the required details and click **Generate**.
4. Once created, the new credentials can be viewed in the **My Apps & Tokens** tab.

See [Creating Application & Token](https://developer.arubanetworks.com/hpe-aruba-networking-central/docs/api-gateway-creating-application-token) for more details.


### Domain URLs for API Gateway Access

| **Region** | **API Gateway Domain Name** |
| --- | --- |
| US-1 | <https://app1-apigw.central.arubanetworks.com> |
| US-2 | <https://apigw-prod2.central.arubanetworks.com> |
| US-East1 | <https://apigw-us-east-1.central.arubanetworks.com> |
| US-West4 | <https://apigw-uswest4.central.arubanetworks.com> |
| EU-1 | <https://eu-apigw.central.arubanetworks.com> |
| EU-Central2 | <https://apigw-eucentral2.central.arubanetworks.com> |
| EU-Central3 | <https://apigw-eucentral3.central.arubanetworks.com> |
| Canada-1 | <https://apigw-ca.central.arubanetworks.com> |
| China-1 | <https://apigw.central.arubanetworks.com.cn> |
| APAC-1 | <https://api-ap.central.arubanetworks.com> |
| APAC-EAST1 | <https://apigw-apaceast.central.arubanetworks.com> |
| APAC-SOUTH1 | <https://apigw-apacsouth.central.arubanetworks.com> |
| UAE-NORTH1 | <https://apigw-uaenorth1.central.arubanetworks.com> |

## How to Find Required Parameters

You can find most of the required API credentials within your HPE Aruba Central account.

1.  Log in to your **Aruba Central** account.
2.  Navigate to the **Global Settings** menu (or the equivalent management scope).
3.  Select **API Gateway**.

From this section, you can retrieve the following information:

* **Access Token URL:** Found on the **APIs** tab.
* **Customer ID:** Found on the **APIs** tab.
* **Server URL:** This is the base domain of your Aruba Central portal (e.g., `https://app-uswest4.central.arubanetworks.com`).
* **Client ID & Client Secret:** Found on the **My Apps** tab. Select the application you created for XSOAR to view its details.

**User Credentials:**

* **Username & Password:** These are the credentials for the Aruba Central user account that you used to generate the API application (Client ID and Secret). This account must have at least read-only privileges.
