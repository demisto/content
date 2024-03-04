## SafeBreach Simulations & Insights
This integration leverages SafeBreach simulation results and insights to remediate malicious indicators that expose your environment to real risks.

  To configure the integration on SafeBreach:
  1. Open the **Navigation bar** → … → **CLI Console**.
  2. Type **config accounts** to get the account id.
  3. Use the id as the **accountId** parameter when configuring the SafeBreach integration in Cortex XSOAR.
  4. Type **config apikeys** to list existing API keys \
  OR \
  Add a new one by typing: **config apikeys add --name <key_name>**
  5. Use the generated API token as **apiKey** parameter when configuring the SafeBreach integration in Cortex XSOAR.
  6. Use your SafeBreach Management URL as the **url** parameter when configuring the SafeBreach integration in Cortex XSOAR.

## Configure Safebreach on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Safebreach.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | This is base URL for your instance. | True |
    | API Key | This is API key for your instance, this can be created in safebreach user                       administration&gt;APIkeys and then it must be saved as there is no way to view this again | True |
    | Account ID | This is account ID of account with which we want to get data from safebreach | True |
    | Verify SSL Certificate | This Field is useful for checking if the certificate of SSL for HTTPS is valid or not | False |
    | Use system proxy settings | This Field is useful for asking integration to use default system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.