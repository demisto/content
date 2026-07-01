## Securiti Event Collector

This integration collects audit trail events from Securiti for Cortex XSIAM.

### Authentication

The Securiti API uses API keys to authenticate requests. You can view and manage your API keys in Securiti under System Settings > Integrations > Credentials > API Keys:

1. Log into Securiti with your admin credentials.
2. Click **Settings**, then choose **Integrations > Credentials > API Keys** and provision an API key of type **User**.
3. Download the key and its secret and keep them safe. Your Securiti access permissions are inherited by the API key. You can provision multiple keys and use them with different applications. Ideally, you should use a "service" user account for such API keys.
4. Pass the key and secret as the **API Key** and **API Secret** parameters respectively.
5. Set the **Tenant Identifier** value which you can retrieve from **Securiti > Settings > General > Basic Information**.

**Note:** It may take up to 30 seconds for the system to report audit trails.
