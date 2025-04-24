## Team Cymru Scout Help

Use the Team Cymru Scout integration to get enriched data for IP addresses.
This guide assists you in setting up the Team Cymru Scout integration on Cortex XSOAR to get enriched data for IP addresses.

## Prerequisites

- Access to the [Team Cymru Scout platform](https://scout.cymru.com/scout).
- An API Key or Basic Auth credentials for authentication.

### Generate API Keys

If you prefer to use an API key for authentication, you can generate one as follows:

1. Go to the [API Keys page](https://scout.cymru.com/api_keys).
2. Click  **Create**.
3. Provide the description for the key, if needed.
4. Click **Create Key** to generate the API key.

Note:

- The number of API keys allowed for each organization is equal to the number of user seats. Therefore, an individual user may have multiple keys, but all the users in your organization may have a maximum of 5 keys. The [API Keys page](https://scout.cymru.com/api_keys) shows the total number of keys used by your organization.
- If the "Create" button is disabled, it indicates that you have reached the maximum number of keys allowed for your organization. To generate a new key, you need to:
  - Click **Revoke** next to an old key.
  - Click  **Create Key** to start generating a new key.

### Configuration Parameters

Before you start running the commands, you need to configure the integration parameters:

1. Authentication Type: Select the authentication type used for secure communication with the Team Cymru Scout platform.
2. API Key: The API key used for secure communication with the Team Cymru Scout platform. Required if "API Key" as  Authentication Type is selected.
3. Username and Password: The username and password used for secure communication with the Team Cymru Scout platform. Required if "Basic Auth" as Authentication Type is selected.
4. Source Reliability: Select the reliability of the source providing the intelligence data.
5. Create relationships: Select whether to create relationships between indicators as part of enrichment.

After configuring the integration parameters, you can click **Test** to ensure that the connection to the Team Cymru Scout platform is successful.
