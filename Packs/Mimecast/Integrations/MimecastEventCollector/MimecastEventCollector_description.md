## Mimecast Event Collector

**Note**: Following [the announcement about Mimecast API 1.0 End of Life](https://mimecastsupport.zendesk.com/hc/en-us/articles/39704312201235-API-Integrations-API-1-0-End-of-Life-Mar-2025), the legacy authentication model (using Application ID, Application Key, Access Key, and Secret Key) is no longer supported by this integration. This has been replaced by the new OAuth2 client credentials flow in Mimecast API 2.0.

### Client ID and Client Secret

1. Log in to the Mimecast Administration Console.

2. Navigate to **Integrations** > **API and Platform Integrations** > **Application Integrations**.

3. Under the **Available Integrations** tab, select **Mimecast API 2.0** and click **Generate Keys**.

4. Specify the application details, such as the name and description, and select a suitable role:
    - To fetch audit logs, ensure the role assigned to the application is granted the **Account | Logs | Read** permission.
    - To fetch SIEM logs, the logged-in user must be a Mimecast Administrator with the **Security Events and Data Retrieval | Threat and Security Events (SIEM) | Read** permission or higher.

5. Once the application is created, retrieve the **Client ID** and **Client Secret**, store them in a secure location, and use them to configure an instance of this integration.

### Base URL

Use `https://api.services.mimecast.com` for the Global region or review the [Mimecast guide on per-region Base URLs](https://integrations.mimecast.com/documentation/api-overview/global-base-urls/) to find the suitable Base URL.
