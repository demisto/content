Digital Shadows (Relia Quest) monitors and manages an organization's digital risk across the widest range of data sources within the open, deep, and dark web.


## Configure Relia Quest GreyMatter DRP EventCollector On XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for Saas Security Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | URL for the Relia Quest API instance. | True |
    | Account ID | The account ID for the Reila Quest instance. | True |
    | Maximum number of events per fetch | The maximum number of events to fetch every time fetch is being executed. | True |
    | Trust any certificate (not secure) | By default, SSL verification is enabled. If selected, the connection isn’t secure and all requests return an SSL error because the certificate cannot be verified. | False |
    | Use system proxy settings | Uses the system proxy server to communicate with the  integration. If not selected, the integration will not use the system proxy server. | False |
    | User Name | The maximum number of events to fetch every time fetch is being executed. This number must be divisible by 100 due to Saas-Security api limitations. Default is 1000. In case this is empty, all available events will be fetched. | False |
    | Password | In order to prevent timeouts, set this parameter to limit the number of iterations for retrieving events. Note - the default value is the recommended value to prevent timeouts. Default is 150. | False |
5. Click **Test** to validate the URLs, token, and connection.

