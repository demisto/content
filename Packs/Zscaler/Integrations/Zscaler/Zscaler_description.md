# Authentication

The Zscaler Internet Access (ZIA) integration supports two methods of authentication:

1. **OAuth 2.0 (Client Credentials)**: This is the recommended method. It uses a Client ID and Client Secret for secure, token-based API access.
2. **Basic Authentication**: This method uses a traditional API Key and Username.

## OAuth 2.0 Configuration Guide

Configuring OAuth 2.0 is a multi-stage process that involves configuring both your Identity Provider (IdP) and the Zscaler Internet Access (ZIA) Admin Portal.

## Stage 1: Zscaler Prerequisites

Before configuring your identity provider, you must complete the following prerequisite steps within the ZIA Admin Portal.

### 1. Verify API Subscription

Ensure that your organization has an active Zscaler API subscription. If you do not have one, please submit a ticket to Zscaler Support to enable it.

### 2. Configure an API Role

Create a dedicated role to define the access permissions for the Cortex integration.

1. In the ZIA Admin Portal, navigate to **Administration > Role Management**.
2. Click **Add API Role**.
3. In the **General Information** section, provide a **Name** for the role (e.g., Cortex API Role).
4. In the **API Permissions** section, select the required **Functional Scope** (permissions) for the integration.
5. Click **Save**. Note the exact role name, as it is required in a later stage.

## Stage 2: Identity Provider (IdP) Configuration

In this stage, you will register the Cortex application within your organization's identity provider. This process generates the Client ID and Client Secret required for authentication.

1. Log in to the administrative console of your OAuth provider (e.g., Zscaler, Okta, Microsoft Entra ID, PingFederate).
2. Follow the official Zscaler guide for your specific provider to register a new client application, define the required Zscaler API scope, and generate credentials:
   - 📄 [Configuration Guide for Microsoft Entra ID](https://help.zscaler.com/zia/oauth-2.0-configuration-guide-microsoft-entra-id)
   - 📄 [Configuration Guide for Okta](https://help.zscaler.com/zia/oauth-2.0-configuration-guide-okta)
   - 📄 [Configuration Guide for PingFederate](https://help.zscaler.com/zia/oauth-2-0-configuration-guide-pingfederate)
3. From your identity provider, collect and securely store the following information:
   - **Client ID**
   - **Client Secret** (This is often displayed only once.)
   - **OAuth 2.0 Token Endpoint URL**

## Stage 3: Zscaler Authorization Server Configuration

This final configuration step registers your identity provider with Zscaler, establishing a trust relationship.

1. In the ZIA Admin Portal, navigate to **Administration > Cloud Service API Security**.
2. Select the **OAuth 2.0 Authorization Servers** tab.
3. Click **Add Authorization Server**.
4. Enter the required information from your identity provider, such as the **Issuer** and **JSON Web Key Set (JWKS) URL**, as detailed in the guides from Stage 2.

## Stage 4: Cortex Integration Instance Configuration

After completing the steps above, you will have all the necessary information to configure the Zscaler integration instance in Cortex.

### Required Configuration Parameters

**For OAuth 2.0 Authentication:**
- **OAuth Credentials**: Enter Client ID as username and Client Secret as password
- **OAuth Token URL**: The token endpoint URL obtained from your OAuth provider in Stage 2
- **Cloud Name**: Your organization's Zscaler cloud name (e.g., `https://zsapi.zscalertwo.net`)
- **Organization ID**: Found in the ZIA Admin Portal under **Administration > Company Profile**
- **API Role**: The exact name of the role created in Stage 1

**For Basic Authentication:**
- **Username**: Your Zscaler username
- **API Key**: Your Zscaler API key
- **Cloud Name**: Your organization's Zscaler cloud name

### Example Configuration

- **OAuth Token URL**: `https://your-org.okta.com/oauth2/v1/token`
- **Cloud Name**: `https://zsapi.zscalertwo.net`
- **Organization ID**: `123456`
- **API Role**: `Cortex_API_Role`

For detailed configuration steps, refer to official documentation:

- <https://help.zscaler.com/zia/getting-started-zia-api>
- <https://help.zscaler.com/zia/adding-api-roles>
- <https://help.zscaler.com/zia/managing-oauth-2.0-authorization-servers>

[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/zscaler)
