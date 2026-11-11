## SOCFWPackManager

Internal HTTP layer used by the **SOCFWPackManager** script. End users run the script, not this integration directly.

### Create an API key

1. Navigate to **Settings** > **Configurations** > **API Keys** and create a Standard API key.
2. Copy the **Key** and note its numeric **ID** from the table.
3. Click **Copy URL** to capture the tenant Server URL.

### Configure the instance

| Parameter | Value |
| --- | --- |
| Server URL | The copied tenant URL. The integration adds the `api-` prefix when it is missing. |
| API Key ID | The numeric ID from the API Keys table. |
| API Key | The secret value of the key. Stored masked. |
| Pack catalog URL | Optional. Location of the SOC Framework `pack_catalog.json`. Leave empty to use the SOC Framework repository. |

The API key requires the **Instance Administrator** role, because installing content as system content and creating integration instances cannot be delegated to a custom role.

Click **Test** to confirm the URL and credentials, then **Done**.
