## O365 Message Trace

## Prerequisites

### Register an application

Register an app in the Microsoft identity platform. For step-by-step instructions, see [Register an application with the Microsoft identity platform](https://learn.microsoft.com/en-us/graph/auth-register-app-v2).

During registration, record the following information:

- The **Application (client) ID**
- One of the following credentials:
  - A client secret
  - A certificate
  - A federated identity credential

### Configure Microsoft Graph permissions

Grant your application the required application permissions in Microsoft Entra ID.

1. In the **Microsoft Entra admin center**, open **App registrations**, and then select your app.
2. Select **API permissions**, and then choose **Add a permission**.
3. Select **Microsoft Graph**, and then select **Application permissions**.
4. Add the **`ExchangeMessageTrace.Read.All`** permission.
5. Grant **admin consent** for your tenant.

> **Important:** To use the Graph-based message trace API, you must provision a service principal in your tenant for the Microsoft application with the following application (client) ID: `8bd644d1-64a1-4d4b-ae52-2e0cbf64e373`.

This step creates a local representation of the multi-tenant Microsoft application in your tenant and enables authentication and authorization. For more background information, see [Create an enterprise application from a multitenant application](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/create-service-principal-cross-tenant?pivots=ms-graph).

### Create the service principal by using Microsoft Graph Explorer

You can provision the service principal by calling Microsoft Graph.

1. Go to [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer).
2. Sign in with an account that has administrator permissions in the tenant where you want to create the service principal.
3. Run the following request:

```http
POST https://graph.microsoft.com/v1.0/servicePrincipals
{
    "appId" : "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373"
}
```

> **IMPORTANT:** After you create the service principal, provisioning might take several hours to complete (up to 24 hours). During this time, requests to the Graph-based message trace API can return `401 (Unauthorized)` errors:
>
> `Service principal-less authentication failed: The service principal for App ID 8bd644d1-64a1-4d4b-ae52-2e0cbf64e373 was not found. Please create a service principal for this app in your tenant. Provisioning may take several hours to complete.`

> **DISCLAIMER:** Message Trace **Detail** is **NOT SUPPORTED**.

## Authentication

Microsoft integrations (Graph and Azure) in Cortex XSIAM use Entra ID applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard compliant authentication services, which use an application to sign in or delegate authentication. For more information, see the Microsoft identity platform overview.

This integration uses the **[Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)** authentication method.

To configure authentication, register your own application in Microsoft Entra ID (as described in the [Prerequisites](#prerequisites) section above), grant the required `ExchangeMessageTrace.Read.All` permission, and provide the **Tenant ID**, **Client ID**, and **Client Secret** (or certificate) in the integration instance settings.

This integration uses the **OAuth 2.0 Client Credentials** flow against the Microsoft identity platform:

```
POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=https://graph.microsoft.com/.default&client_id={client_id}&client_secret={client_secret}
```

Azure Managed Identity authentication is also supported by enabling the **Use Azure Managed Identity** parameter (only available when running inside Azure).

### Required API Permissions

The Azure AD application must be granted the following Microsoft Graph application permission (admin consent required):

- `ExchangeMessageTrace.Read.All`

### Required Configuration

| Parameter | Description |
| --- | --- |
| Server URL | Microsoft Graph base URL (default: `https://graph.microsoft.com`). |
| Tenant ID | The Azure AD tenant ID. |
| Client ID | The Application (Client) ID registered in Azure AD. |
| Client Secret | The client secret for the Azure AD application. |
| Use Azure Managed Identity | Use Azure Managed Identity for authentication instead of client secret. |
| Maximum number of events | Max events to fetch per cycle (default: 50000). |

### Reference

- [Microsoft Graph - Get message traces](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/graph-api-message-trace#get-beta-admin-exchange-tracing-messageTraces)
- [Paging Microsoft Graph data in your app](https://learn.microsoft.com/en-us/graph/paging)
