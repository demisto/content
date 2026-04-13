## Mimecast Event Collector v2

### Client ID and Client Secret

Follow these steps in your Mimecast Administration Console to obtain OAuth2 client credentials:

1. Log in to the Mimecast Administration Console.

2. Navigate to **Integrations** > **API and Platform Integrations** > **Application Integrations**.

3. Under the **Available Integrations** tab, select **Mimecast API 2.0** and click **Generate Keys**.

4. Specify the application details, such as the name and description, and select a suitable role:
    - To fetch Audit events, ensure the role assigned to the application is granted the **Account | Logs | Read** permission.
    - To fetch SIEM logs, the logged-in user must be a Mimecast Administrator with the **Security Events and Data Retrieval | Threat and Security Events (SIEM) | Read** permission or higher.

5. Once the application is created, retrieve the **Client ID** and **Client Secret**, store them in a secure location, and use them to configure an instance of this integration.

### Base URL

Use the https://api.services.mimecast.com/ Base URL for the Global region. See the [Mimecast guide on API Gateway Options](https://developer.services.mimecast.com/api-overview#api-gateway-options) to find the relevant Base URL for other regions.
