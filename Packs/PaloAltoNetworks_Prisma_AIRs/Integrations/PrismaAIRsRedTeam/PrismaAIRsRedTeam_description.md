### Prerequisites

Before configuring this integration, you need:

1. **Strata Cloud Manager Access**: Active Prisma SASE account with Strata Cloud Manager access
2. **OAuth2 Credentials**: Create an OAuth2 client in Strata Cloud Manager with Prisma AIRS AI Red Teaming API permissions
3. **Tenant Services Group ID**: Your Prisma SASE TSG ID (found in Strata Cloud Manager settings)

### Configuration Steps

1. **Create OAuth2 Client in Strata Cloud Manager**:
   - Navigate to Settings > Identity & Access
   - Create a new service account or OAuth2 client
   - Assign Prisma AIRS AI Red Teaming API permissions
   - Copy the Client ID and Client Secret

2. **Configure the Integration**:
   - Add the integration instance in Cortex XSOAR
   - Enter the **API Client ID and API Client Secret** (OAuth2 credentials for the management API)
   - Provide your **Tenant Services Group ID** (TSG ID)
   - Test the connection

3. **Accept the EULA**:
   - Red Teaming operations require accepting the End User License Agreement.
   - Use `prisma-airs-redteam-eula-status` to check acceptance, `prisma-airs-redteam-eula-content` to review it, and `prisma-airs-redteam-eula-accept` to accept.

**Note**: The Server URL (`api.sase.paloaltonetworks.com`) is a global endpoint and does not require regional configuration.

For detailed documentation, see the integration README.
