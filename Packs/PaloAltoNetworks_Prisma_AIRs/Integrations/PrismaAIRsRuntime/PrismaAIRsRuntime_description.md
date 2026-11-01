### Prerequisites

Before configuring this integration, you need:

1. **Strata Cloud Manager Access**: Active Prisma SASE account with Strata Cloud Manager access
2. **OAuth2 Credentials**: Create an OAuth2 client in Strata Cloud Manager with Prisma AIRS AI Runtime Security API permissions
3. **Tenant Services Group ID**: Your Prisma SASE TSG ID (found in Strata Cloud Manager settings)

### Configuration Steps

1. **Create OAuth2 Client in Strata Cloud Manager**:
   - Navigate to Settings > Identity & Access
   - Create a new service account or OAuth2 client
   - Assign Prisma AIRS AI Runtime Security API permissions
   - Copy the Client ID and Client Secret

2. **Generate Runtime API Key**:
   - In Strata Cloud Manager, navigate to AI Security > API Applications
   - Click Manage > API Keys
   - Copy the Runtime API Key for scanner operations
   - **Note**: This is different from the OAuth2 Client ID/Secret used for management operations

3. **Configure the Integration**:
   - Add the integration instance in Cortex XSOAR
   - Enter the **API Client ID and API Client Secret** (OAuth2 credentials for the management API)
   - Provide your **Tenant Services Group ID** (TSG ID)
   - Enter the **Runtime API Key** (for runtime scanning operations only)
   - Optionally set the **Scanner API Base URL** (must match your deployment profile region) and **DLP API Base URL**
   - Test the connection

**Note**: The Server URL (`api.sase.paloaltonetworks.com`) is a global endpoint and does not require regional configuration. Only the Scanner API base URL is region-specific.

For detailed documentation, see the integration README.
