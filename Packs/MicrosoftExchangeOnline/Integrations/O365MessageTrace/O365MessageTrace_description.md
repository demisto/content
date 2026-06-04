## O365 Message Trace

Ingest Exchange Online Message Trace events into Cortex XSIAM. Message Trace enables tenant administrators to track the lifecycle of an email, determine its delivery status (delivered, pending, failed, or quarantined), and understand the actions applied to it.

### Authentication

This integration uses the **OAuth 2.0 Client Credentials** flow against Microsoft identity platform:

```
POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=https://graph.microsoft.com/.default&client_id={client_id}&client_secret={client_secret}
```

Azure Managed Identity authentication is also supported by enabling the **Use Azure Managed Identity** parameter (only available when running inside Azure).

### Required API Permissions

The Azure AD application must be granted the following Microsoft Graph application permission (admin consent required):

- `MessageTrace.Read.All`

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
