## SAP BTP (Business Technology Platform) - Event Collector

This integration collects audit log events from SAP Business Technology Platform (BTP).

### How to Configure the Integration Instance

Follow these steps to configure the SAP BTP Event Collector:

### Authentication Methods

The integration supports two authentication methods:

#### 1. mTLS Authentication (Recommended)
- **Certificate**: PEM-encoded certificate from your SAP Service Key
- **Private Key**: PEM-encoded private key from your SAP Service Key
- **Client ID**: The `uaa.clientid` field from your SAP Service Key
- **Token URL**: The `uaa.certurl` field from your SAP Service Key (for mTLS authentication)

#### 2. Non-mTLS Authentication
- **Client ID**: The `uaa.clientid` field from your SAP Service Key
- **Client Secret**: The `uaa.clientsecret` field from your SAP Service Key
- **Token URL**: The `uaa.url` field from your SAP Service Key (for Non-mTLS authentication)

### How to Obtain SAP Service Key Credentials

1. Log in to your SAP BTP Cockpit
2. Navigate to your subaccount
3. Go to **Services** > **Instances and Subscriptions**
4. Find your Audit Log service instance
5. Click on the instance and select **Create Service Key**
6. Download or copy the service key JSON

The service key contains:
- `url`: API URL for Audit Log Service (use this for the integration's **API URL** parameter)
- `uaa.url`: Token URL for Non-mTLS authentication (e.g., `https://<subdomain>.authentication.<region>.hana.ondemand.com`)
- `uaa.certurl`: Token URL for mTLS authentication (e.g., `https://<subdomain>.authentication.cert.<region>.hana.ondemand.com`)
- `uaa.clientid`: Client ID (required for both authentication methods)
- `uaa.clientsecret`: Client Secret (required for Non-mTLS only)
- `certificate`: Certificate content in PEM format (required for mTLS only)
- `key`: Private key content in PEM format (required for mTLS only)

### Configuration Parameters

- **API URL**: Use the `url` field from your service key (e.g., `https://auditlog-management.cfapps.us10.hana.ondemand.com`)
- **Token URL**:
  - For **Non-mTLS**: Use the `uaa.url` field (e.g., `https://<subdomain>.authentication.<region>.hana.ondemand.com`)
  - For **mTLS**: Use the `uaa.certurl` field (e.g., `https://<subdomain>.authentication.cert.<region>.hana.ondemand.com`)
- **Authentication Type**: Select either "mTLS" (recommended) or "Non-mTLS"
- **Client ID**: The `uaa.clientid` field from your service key
- **Client Secret**: Required only for Non-mTLS authentication (`uaa.clientsecret`)
- **Certificate**: Required only for mTLS authentication (PEM format)
- **Private Key**: Required only for mTLS authentication (PEM format)
- **First Fetch Time**: (Optional) Leave empty to start from current time. Only configure if you need to fetch historical data (e.g., "3 days", "1 week").
- **Max Fetch**: Maximum number of events to fetch per cycle (default: 5000, advanced setting)

### Important Notes

- **First Run Behavior**: By default, the collector starts from the current time and does not fetch historical data. This prevents overwhelming the system with old events.
- **get-events Command**: This command is for debugging only and should be used with caution. It can create duplicate events if `should_push_events` is set to true.
- **XSOAR Compatibility**: The `sap-btp-get-events` command is not supported in XSOAR environments.

### Troubleshooting

- If you receive authentication errors, verify that:
  - Your **Client ID** is correct
  - For **Non-mTLS**: The **Client Secret** and **Token URL** (`uaa.url`) are correct
  - For **mTLS**: The **Certificate**, **Private Key**, and **Token URL** (`uaa.certurl`) are correct and in PEM format
- Ensure the **API URL** matches the `url` field in your service key exactly
- Verify the **Token URL** corresponds to your chosen authentication type:
  - Non-mTLS uses `uaa.url`
  - mTLS uses `uaa.certurl`

### Additional Resources

For more information about SAP BTP Audit Log configuration and authentication, refer to the official SAP documentation:

- **Create Instance of the auditlog-management Service**: [SAP Help Portal - Create Instance](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#create-instance-of-the-auditlog-management-service)
- **OAuth Access Token Creation**: [SAP Help Portal - OAuth Access](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#create-an-oauth-access-token)
