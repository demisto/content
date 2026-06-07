Ingest Exchange Online Message Trace events into Cortex XSIAM. Message Trace enables tenant administrators to track the lifecycle of an email, determine its delivery status (delivered, pending, failed, or quarantined), and understand the actions applied to it.

This integration was integrated and tested with the Graph-based Message Trace API (`v1.0/admin/exchange/tracing/messageTraces`).

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

For more background information, see [Create an enterprise application from a multitenant application](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/create-service-principal-cross-tenant?pivots=ms-graph).

### Create the service principal by using Microsoft Graph Explorer

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

Microsoft integrations (Graph and Azure) in Cortex XSIAM use Entra ID applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard compliant authentication services, which use an application to sign in or delegate authentication.

This integration uses the **[Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)** authentication method.

To configure authentication, register your own application in Microsoft Entra ID (as described in the [Prerequisites](#prerequisites) section above), grant the required `ExchangeMessageTrace.Read.All` permission, and provide the **Tenant ID**, **Client ID**, and **Client Secret** (or certificate) in the integration instance settings.

In addition to client credentials and certificate authentication, the integration also supports:

- **Authorization Code Flow** (self-deployed) — using the `Application redirect URI` and `Authorization code` parameters together with the `o365-message-trace-generate-login-url` and `o365-message-trace-auth-test` commands.
- **Azure Managed Identities** — when the integration runs on an Azure VM with an assigned identity.

The integration uses the **OAuth 2.0 Client Credentials** flow by default:

```http
POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=https://graph.microsoft.com/.default&client_id={client_id}&client_secret={client_secret}
```
Azure Managed Identity authentication is also supported by enabling the **Use Azure Managed Identity** parameter (only available when running inside Azure).

### Required API Permissions

The Azure AD application must be granted the following Microsoft Graph application permission (admin consent required):

- `ExchangeMessageTrace.Read.All`

### Reference

- [Microsoft Graph - Get message traces](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/graph-api-message-trace#get-beta-admin-exchange-tracing-messageTraces)
- [Paging Microsoft Graph data in your app](https://learn.microsoft.com/en-us/graph/paging)


## Configure O365 Message Trace in Cortex XSIAM

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Microsoft Graph base URL. | True |
| Tenant ID | The customer Azure AD tenant ID \(GUID\). | True |
| Client ID | The Application \(Client\) ID registered in Azure AD. | True |
| Client Secret | The client secret for the Azure AD application. | False |
| Certificate Thumbprint | The private key of the registered certificate used for certificate authentication, as it appears in the "Certificates &amp;amp; secrets" page of the app. | False |
| Private Key |  | False |
| Application redirect URI (for self-deployed mode) | The redirect URI configured in the Azure AD application. Required for the self-deployed authorization-code flow. | False |
| Authorization code | The authorization code received from the Azure portal during the self-deployed authorization-code flow. | False |
| Use Azure Managed Identities | Whether to use Azure Managed Identities when running on an Azure VM with assigned identity. | False |
| Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on an Azure VM. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Maximum number of events per fetch | The maximum number of events to fetch in a single fetch cycle. | False |
| Fetch events |  | False |
| Events Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### o365-message-trace-generate-login-url

***
Generate the login URL used for authorization code flow.

#### Base Command

`o365-message-trace-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Human Readable Output

A login URL that the administrator can use to grant consent and obtain an authorization code. After consent, the resulting authorization code should be pasted into the **Authorization code** integration parameter, followed by running `o365-message-trace-auth-test` to verify the configuration.

---

### o365-message-trace-auth-test

***
Tests connectivity to Microsoft.

#### Base Command

`o365-message-trace-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Human Readable Output

`Authentication was successful.` on success; otherwise an error message describing the failure.

---

### o365-message-trace-auth-reset

***
Run this command if for some reason you need to rerun the authentication process. This will clear the saved access token / refresh token from the integration context, so on the next run a fresh authorization code (or client-credentials token) will be requested.

#### Base Command

`o365-message-trace-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

---

### o365-message-trace-get-events

***
Manually retrieve Message Trace events. Intended for development and debugging. Use with caution as it may cause event duplication when push to XSIAM is enabled.

#### Base Command

`o365-message-trace-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to return. Default is 50. | Optional | 
| start_time | The start time to filter events received at or after this time. Supports ISO 8601 format or relative time expressions (e.g., "10 minutes ago", "2024-01-01T00:00:00Z"). | Optional | 
| end_time | The end time to filter events received at or before this time. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). | Optional | 
| should_push_events | Whether the command sends the retrieved events to XSIAM. If false, it only displays them. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365MessageTrace.Event.id | String | The unique identifier of the message trace event. | 
| O365MessageTrace.Event.receivedDateTime | Date | The timestamp when the message was received \(e.g., "2020-01-01T00:11:22Z"\). | 
| O365MessageTrace.Event.senderAddress | String | The sender email address. | 
| O365MessageTrace.Event.recipientAddress | String | The recipient email address. | 
| O365MessageTrace.Event.subject | String | The subject of the message. | 
| O365MessageTrace.Event.status | String | The delivery status of the message \(e.g., Delivered, Pending, Failed, Quarantined\). | 
| O365MessageTrace.Event._time | Date | The XSIAM event timestamp in ISO 8601 format \(e.g., "2020-01-01T00:11:22Z"\). | 

#### Command example

```!o365-message-trace-get-events limit=2 start_time="10 minutes ago"```

#### Human Readable Output

>### O365 Message Trace Events
>
>| Id | Received Date Time | Sender Address | Recipient Address | Subject | Status |
>| --- | --- | --- | --- | --- | --- |
>| 2bd1c8...e9 | 2025-01-01T10:05:23Z | sender@contoso.com | recipient@contoso.com | Hello World | Delivered |
>| 9f4ea2...11 | 2025-01-01T10:06:01Z | other@contoso.com | recipient@contoso.com | Test | Pending |
