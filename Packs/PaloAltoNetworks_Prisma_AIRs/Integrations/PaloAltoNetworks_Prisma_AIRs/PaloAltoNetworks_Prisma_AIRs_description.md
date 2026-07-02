## Palo Alto Networks - Prisma AIRs AI Security

Integrate with Palo Alto Networks Prisma AIRs to secure AI applications with runtime scanning, red teaming, and model security capabilities.

### Prerequisites

Before configuring this integration, you need:

1. **Strata Cloud Manager Access**: Active Prisma SASE account with Strata Cloud Manager access
2. **OAuth2 Credentials**: Create an OAuth2 client in Strata Cloud Manager with Prisma AIRs API permissions
3. **Tenant Services Group ID**: Your Prisma SASE TSG ID (found in Strata Cloud Manager settings)

### Configuration Steps

1. **Create OAuth2 Client in Strata Cloud Manager**:
   - Navigate to Settings > Identity & Access
   - Create a new service account or OAuth2 client
   - Assign Prisma AIRs API permissions
   - Copy the Client ID and Client Secret

2. **Generate Runtime API Key**:
   - In Strata Cloud Manager, navigate to AI Security > API Applications
   - Click Manage > API Keys
   - Copy the Runtime API Key for scanner operations
   - **Note**: This is different from the OAuth2 Client ID/Secret used for management operations

3. **Configure the Integration**:
   - Add the integration instance in XSOAR
   - Enter the **API Client ID and API Client Secret** (OAuth2 credentials for management API)
   - Provide your **Tenant Services Group ID** (TSG ID)
   - Enter the **Runtime API Key** (for runtime scanning operations only)
   - Select the **Scanner API Region** (must match your deployment profile region)
   - Test the connection

**Note**: The Server URL (`api.sase.paloaltonetworks.com`) is a global endpoint and does not require regional configuration. Only the Scanner API requires region selection.

### Supported Capabilities

- **Runtime Scanning**: Real-time AI threat detection
- **Security Profiles**: Manage AI security policies
- **Topic Guardrails**: Custom topic-based protection
- **DLP Integration**: Data loss prevention for AI applications

For detailed documentation, see the integration README.