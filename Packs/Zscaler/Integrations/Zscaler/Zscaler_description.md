## Authentication Methods

Zscaler Internet Access integration supports two authentication methods:

1. **OAuth 2.0 (Recommended)** - Uses client credentials for secure API access
2. **Basic Authentication** - Traditional username/password authentication

## OAuth 2.0 Prerequisites

Your organization must meet the following requirements to use OAuth 2.0 authentication:

**Prerequisite 1: API Subscription**
You must have an API subscription. If you do not have a subscription, submit a Zscaler Support ticket.

**Prerequisite 2: API Roles Configuration**
You must have the API Roles configured in the ZIA Admin Portal.
1. Navigate to **Administration > API Roles**, click **Add**
2. Configure: Name, Functional Scope (ZIA modules)
3. Save and note the exact role name

**Prerequisite 3: OAuth Authorization Server Registration**
You must have your client applications registered on your authorization server (i.e., PingFederate, Okta, or Azure AD) with the required scope and configured appropriately.

**Prerequisite 4: OAuth Authorization Server in ZIA Admin Portal**
You must have your OAuth 2.0 authorization server added to the ZIA Admin Portal.

**Configuration Steps:**

**Step 1: Create API Client**
1. Navigate to **Administration > API Client Management**, click **Add**
2. Configure the API client settings
3. Save and securely store the **Client ID** and **Client Secret** (shown only once)

**Step 2: Gather Information**
- **Cloud Name**: Your Zscaler instance URL
- **Organization ID**: Found in **Administration > Company Profile**
- **API Role**: Exact name from Step 1
- **Client ID**: From API Client Management
- **Client Secret**: From API Client Management

For detailed configuration steps, refer to official documentation:
- <https://help.zscaler.com/zia/getting-started-zia-api>
- <https://help.zscaler.com/zia/adding-api-roles>
- <https://help.zscaler.com/zia/managing-oauth-2.0-authorization-servers>


[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/zscaler)
