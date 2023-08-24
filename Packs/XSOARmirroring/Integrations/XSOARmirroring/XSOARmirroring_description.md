## Configuration

### Server URL
To get your server URL
  - XSOAR 6.X: just use the URL of the server you are trying to connect to.
  To access a Cortex XSOAR server which is in a Multi-tenant environment you should add the full path, i.e. https://xsoar_dns_address:8443/acc_MyTenant/
  - XSOAR 8.X: Navigate to Setting > API Keys > Copy API URL
  - 
### API key
To gain the API key from Cortex XSOAR which you are connecting to:
  - XSOAR 6.X: Navigate to Setting > API Keys > Get Your Key.
  - XSOAR 8.X: Navigate to Setting > API Keys > +New Key.

### API Key ID
This is required only when connecting to XSOAR 8.X tenants.
After creating your API Key obtain its ID located in the ID column of the API Keys table.