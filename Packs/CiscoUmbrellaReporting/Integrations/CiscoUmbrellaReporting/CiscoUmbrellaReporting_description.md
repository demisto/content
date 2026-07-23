# Cisco Umbrella Reporting

Use Cisco Umbrella's Reporting to monitor your Umbrella integration and gain a better understanding of your Umbrella usage. Gain insights into request activity and blocked activity, determining which of your identities are generating blocked requests. Reports help build actionable intelligence in addressing security threats including changes in usage trends over time.

## How to get Cisco Umbrella Reporting Credentials

### Generate an API Key

Create an Umbrella API key and secret in the Umbrella admin console.

1. In Umbrella, navigate to **Admin** > **API Keys** (or **Settings** > **API Keys** in a Multi-org/MSP/MSSP management console) and click **Add** / **Create**.
2. Provide a name for the key (for example, `Cortex Reporting`) and select an expiration date.
3. Under **Key Scope**, expand **Reports** and grant the key the following scopes (read-only is sufficient for this integration):
    - **Aggregations** – Read
    - **Utilities** – Read
4. Click **Create Key**.
5. Copy **Your Key (API Key)** and **Your Secret (API Secret)**, acknowledge the warning, and click **Close**.

> **Note:** In the current Umbrella admin console, the dedicated "Umbrella Reporting" key type has been replaced by **Umbrella API keys with scoped permissions**. Granting the **Reports** scopes above is what previously was called the "Reporting v2" key.
> If the key is missing any of the required Reports scopes, the integration test will fail with an authorization error from Cisco Umbrella.

For more information, see the official Cisco Umbrella documentation:

- [Add Umbrella API Keys](https://developer.cisco.com/docs/cloud-security/authentication/)
- [Umbrella API OAuth scopes](https://developer.cisco.com/docs/cloud-security/umbrella-api-oauth-scopes/)
- [Reporting v2 authentication](https://developer.cisco.com/docs/cloud-security/#!reporting-v2-authentication/log-into-umbrella)
