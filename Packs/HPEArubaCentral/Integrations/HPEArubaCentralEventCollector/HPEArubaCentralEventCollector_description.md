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

### Authentication

Use the **Authentication Method** selector to choose how to authenticate:

- **Access Token:** In the Aruba Central UI, click the **Download Token** button and paste the copied token JSON into the **Access Token** parameter. The integration uses it to obtain and refresh access tokens automatically, so **no Username, Password, or Customer ID is required**.
- **Basic Auth:** Provide a **Username**, **Password**, and **Customer ID**. The integration then performs the full OAuth login. See [Authenticate a user and create a user session](https://developer.arubanetworks.com/central/docs/api-oauth-access-token#1-authenticate-a-user-and-create-a-user-session).

#### How to get an Access Token

1. Go to **Accounts Home** > **Global Settings** > **API Gateway**.
2. Open the application you created (**My Apps & Tokens**).
3. In the **Token List** table (which shows all generated tokens, including expired ones), click the **Download Token** button to view the generated token.
4. The token is a full **JSON** object. Copy the **entire JSON** and paste it into the **Access Token** parameter.

The token JSON looks like this:

```json
{
  "access_token": "xxxx",
  "appname": "xxx",
  "authenticated_userid": "username@email.com",
  "created_at": 1582847137105,
  "credential_id": "xxxx",
  "expires_in": 7200,
  "id": "xxxx",
  "refresh_token": "xxxx",
  "scope": "all",
  "token_type": "bearer"
}
```

Paste the **entire JSON**. The integration reads the `refresh_token` from it (and uses the `access_token`/`expires_in` to avoid an extra call on the first run).

> Note: You only need to do this once. The integration stores and automatically rotates the refresh token.
>
> Access tokens are valid for 2 hours, and refresh tokens are valid for 15 days. If an access token is not renewed for 15 days (meaning the refresh token is unused for 15 days), Aruba Central removes the token. At this point, a new token must be generated either by going to the API Gateway UI (clicking the **Download Token** button and pasting the new token JSON here) or by using the OAuth API (Basic Auth method).


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

**User Credentials (only for the "Basic Auth" method):**

* **Username and Password:** These are the credentials for the Aruba Central user account that you used to generate the API application (Client ID and Secret). This account must have at least read-only privileges. These are **not** required when using the "Access Token" method.