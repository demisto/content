## SAP BTP (Business Technology Platform) Integration

This integration collects audit log events from SAP Business Technology Platform.

### Authentication Methods

The integration supports two authentication methods:

#### 1. mTLS Authentication (Recommended)
- **Certificate**: PEM-encoded certificate from your SAP Service Key
- **Private Key**: PEM-encoded private key from your SAP Service Key
- **Client ID**: The `uaa.clientid` field from your SAP Service Key

#### 2. Non-mTLS Authentication
- **Client ID**: The `uaa.clientid` field from your SAP Service Key
- **Client Secret**: The `uaa.clientsecret` field from your SAP Service Key

### How to Obtain SAP Service Key Credentials

1. Log in to your SAP BTP Cockpit
2. Navigate to your subaccount
3. Go to **Services** > **Instances and Subscriptions**
4. Find your Audit Log service instance
5. Click on the instance and select **Create Service Key**
6. Download or copy the service key JSON

The service key contains:
- `url`: Server URL (use this for the integration's Server URL parameter)
- `uaa.clientid`: Client ID
- `uaa.clientsecret`: Client Secret (for Non-mTLS)
- `certificate`: Certificate content (for mTLS)
- `key`: Private key content (for mTLS)

### Configuration Notes

- **Server URL**: Use the `url` field from your service key (e.g., `https://auditlog-management.cfapps.us10.hana.ondemand.com`)
- **First Fetch Time**: Determines how far back to fetch events on the first run (e.g., "3 days", "1 week")
- **Max Fetch**: Maximum number of events to fetch per cycle (default: 5000)

### Troubleshooting

- If you receive authentication errors, verify that your Client ID and credentials (Secret or Certificate/Key) are correct
- For mTLS authentication, ensure both Certificate and Private Key are provided in PEM format
- Check that the Server URL matches the `url` field in your service key exactly
