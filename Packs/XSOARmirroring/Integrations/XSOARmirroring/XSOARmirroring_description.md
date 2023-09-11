## Configuration

### Server URL
To obtain the server URL
  - In XSOAR 6.x: simply use the URL of the server you are trying to connect to.
  To access a Cortex XSOAR server in a multi-tenant environment, make sure to include the full path, such as: `https://xsoar_dns_address:8443/acc_MyTenant/`
  - In XSOAR 8.x: Navigate to **Settings** > **API Keys** and click the **Copy API URL** button.

### API key
To gain the API key from Cortex XSOAR which you are connecting to:
  - XSOAR 6.x: Navigate to **Settings** > **API Keys** > Click the **Get Your Key** button.
  - XSOAR 8.x: Navigate to **Settings** > **API Keys** > Click the **+ New Key** button.

### API Key ID
This parameter is required only when connecting to XSOAR 8.x tenants.
After creating your API Key, obtain its ID from the **ID** column of the API Keys table.