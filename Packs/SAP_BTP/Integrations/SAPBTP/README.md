# SAP BTP (Business Technology Platform)

## Overview

SAP Business Technology Platform is a cloud-based platform that enables organizations to build, integrate, and extend applications using data, analytics, AI, and automation tools. It combines database, development, and integration services into a unified environment optimized for enterprise business processes.

This integration collects audit log events from SAP BTP for security monitoring and compliance purposes in your Cortex environment.

## Authentication

This integration supports two authentication methods for connecting to the SAP BTP Audit Log API:

### mTLS (Mutual TLS) - Recommended

Mutual TLS provides the highest level of security by using client certificates for authentication. This method:

- Uses X.509 certificates for mutual authentication between the client and server
- Eliminates the need to manage and rotate client secrets
- Provides stronger security through certificate-based authentication
- Requires a certificate and private key pair generated from your SAP BTP service instance

**When to use**: Recommended for production environments and when enhanced security is required.

### Non-mTLS (Client Credentials)

This method uses OAuth 2.0 client credentials flow with a client ID and client secret:

- Simple to set up initially
- Uses client ID and client secret for authentication
- Requires regular secret rotation according to security policies
- Suitable for development and testing environments

**When to use**: Suitable for development, testing, or when certificate-based authentication is not feasible.

## SAP BTP Architecture

SAP BTP uses **two separate domains** for different purposes:

1. **API URL** (Audit Log Service): Used for fetching audit log events
   - Example: `https://auditlog-management.cfapps.<region>.hana.ondemand.com`
   - Found in Service Key field: `url`

2. **Token URL** (Authentication Service): Used for OAuth2 token generation
   - Example: `https://<subdomain>.authentication.<region>.hana.ondemand.com`
   - Found in Service Key field: `uaa.url`

**Important**: These URLs are on different subdomains and must be configured separately for the integration to work correctly.

### Service Key Example

Your SAP BTP Service Key will look similar to this (with sensitive values replaced):

```json
{
  "uaa": {
    "url": "https://<subdomain>.authentication.<region>.hana.ondemand.com",
    "clientid": "<your-client-id>",
    "clientsecret": "<your-client-secret>",
  },
  "url": "https://auditlog-management.cfapps.<region>.hana.ondemand.com"
}
```

**Key Mappings for Integration Configuration:**

- `url` → **API URL** (Audit Log Service)
- `uaa.url` → **Token URL** (Authentication Service)
- `uaa.clientid` → **Client ID**
- `uaa.clientsecret` → **Client Secret** (for Non-mTLS)

## Before You Start

Before configuring the integration, you must complete the following prerequisites in your SAP BTP environment:

1. **Follow the prerequisites** described in the [SAP BTP Audit Log Retrieval API documentation](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#prerequisites).

2. **Create an instance of the auditlog-management service** as described in the [SAP BTP documentation](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#create-instance-of-the-auditlog-management-service).

3. **Obtain your Service Key** which contains:
   - `url`: The API URL for audit log retrieval
   - `uaa.url`: The Token URL for authentication
   - `uaa.clientid`: The Client ID
   - For **mTLS**: Certificate and private key files
   - For **Non-mTLS**: `uaa.clientsecret`

## Configure SAP BTP (Business Technology Platform) in Cortex

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**
2. Search for SAP BTP (Business Technology Platform).
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API URL (Audit Log Service) | The Service Key `url` field for audit log API calls.<br/>Example: `https://auditlog-management.cfapps.<region>.hana.ondemand.com`<br/>**Note**: This is different from the Token URL. | True |
| Token URL (Authentication Service) | The Service Key `uaa.url` field for OAuth2 authentication.<br/>Example: `https://<subdomain>.authentication.<region>.hana.ondemand.com`<br/>**Important**: This is on a different subdomain than the API URL and is required. | True |
| Client ID | The Service Key `uaa.clientid` field.<br/>Required for both mTLS and Non-mTLS authentication. | True |
| Authentication Type | Select the authentication method:<br/>- **mTLS** (recommended): Uses client certificates<br/>- **Non-mTLS**: Uses client credentials | True |
| Certificate | The body of the certificate.pem file.<br/>Required only when using mTLS authentication. | False |
| Private Key | The body of the key.pem file.<br/>Required only when using mTLS authentication. | False |
| Client Secret | The Service Key `uaa.clientsecret` field.<br/>Required only when using Non-mTLS authentication. | False |
| Trust any certificate (not secure) | When selected, the integration will not verify SSL certificates. | False |
| Use system proxy settings | When selected, the integration will use the system proxy settings. | False |
| Fetch events | Enable automatic collection of audit log events. | False |
| First fetch time | Time range to start fetching events from on first run.<br/>Default: 3 days<br/>Examples: "3 days", "1 week", "2024-01-01" | False |
| The maximum number of audit logs per fetch | Maximum number of events to fetch per collection cycle.<br/>Default: 5000<br/>Note: The API returns a maximum of 500 events per page. | False |

4. Click **Test** to validate the connection and authentication.
5. Click **Done** to save the integration instance.

## How It Works

This integration automatically collects audit log events from SAP BTP and sends them to your Cortex environment for security monitoring and compliance.

1. **Initial Collection**: On the first run, the integration begins collecting events from the configured start time (default: 3 days ago).
2. **Continuous Monitoring**: The integration automatically tracks the last collected event and fetches only new events on subsequent runs.
3. **Automatic Pagination**: The integration handles large result sets automatically, retrieving up to the configured maximum number of events per collection cycle.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### sap-btp-get-events

***
Retrieve audit log events from SAP BTP manually. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and API request limitation exceeding.

**Note**: This command is not supported in XSOAR.

#### Base Command

`sap-btp-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Time to fetch events from. Supports natural language (e.g., "1 minute ago", "3 days", "2 hours", "1 month") or ISO 8601 format (e.g., "2024-01-01T00:00:00Z"). Default is "1 minute ago". | Optional |
| end_time | Time to fetch events until. Supports natural language (e.g., "now", "1 hour ago") or ISO 8601 format (e.g., "2024-01-01T00:00:00Z"). If not specified, fetches until now. | Optional |
| limit | Maximum number of events to retrieve. Default is 5000. | Optional |
| should_push_events | Whether to push the collected events to your Cortex environment. Set to true to send events for ingestion (use with caution to avoid duplicates), false to only return them in the War Room. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SAPBTP.Event.uuid | String | Unique identifier of the event. |
| SAPBTP.Event.user | String | User associated with the event. |
| SAPBTP.Event.time | Date | Timestamp of the event. |
| SAPBTP.Event.ip | String | IP address associated with the event. |
| SAPBTP.Event.data | Unknown | Event data payload. |

#### Human Readable Output

>### SAP BTP (Business Technology Platform) Events
>
>|uuid|user|time|ip|data|
>|---|---|---|---|---|
>| event-uuid-1 | user@example.com | 2024-01-15T10:30:00Z | 192.168.1.1 | {...} |
>| event-uuid-2 | admin@example.com | 2024-01-15T11:45:00Z | 192.168.1.2 | {...} |

## Additional Resources

For more information about SAP BTP Audit Logging, refer to the official SAP documentation:

- [Audit Log Retrieval API Prerequisites](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#prerequisites)
- [Create OAuth Access Token](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#create-an-oauth-access-token)
- [Rate Limiting Rules](https://help.sap.com/docs/btp/sap-business-technology-platform/rate-limiting-rules)

## Best Practices

1. **Use Service Key Fields Directly**: Copy the exact values from your SAP Service Key JSON:
   - `url` → API URL
   - `uaa.url` → Token URL
   - `uaa.clientid` → Client ID
   - `uaa.clientsecret` → Client Secret (for Non-mTLS)
2. **Verify Both URLs**: Ensure both API URL and Token URL are on their correct subdomains (different from each other).
3. **Use mTLS Authentication**: For production environments, always use mTLS authentication with client certificates for enhanced security.
4. **Configure Appropriate Limits**: Set the maximum number of events per fetch based on your organization's event volume.
5. **Secure Credential Storage**: Ensure that authentication credentials (certificates or secrets) are stored securely and rotated regularly according to your organization's security policies.

## Troubleshooting

### 401 Unauthorized Error

If you receive a 401 Unauthorized error, verify:

1. **Token URL is correct**: The Token URL (`uaa.url` from Service Key) must be on the authentication subdomain (e.g., `<subdomain>.authentication.<region>...`), not the API subdomain.
2. **Credentials are valid**: Ensure your Client ID, Client Secret (for Non-mTLS), or Certificate/Private Key (for mTLS) are correct and not expired.
3. **Authentication type matches**: Verify you selected the correct authentication type (mTLS vs Non-mTLS) matching your Service Key configuration.

### 404 Not Found Error

If you receive a 404 error when fetching the token:

1. **Check Token URL**: Ensure the Token URL is the `uaa.url` from your Service Key, not the `url` field.
2. **Verify URL format**: The Token URL should be on the authentication subdomain (e.g., `https://<subdomain>.authentication.<region>.hana.ondemand.com`).
3. **Do not include /oauth/token**: Provide only the base URL from `uaa.url` - the integration automatically appends `/oauth/token`.

### Missing Token URL Error

If you receive an error about missing Token URL:

1. **Provide both URLs**: Both API URL and Token URL are required fields.
2. **Check Service Key**: Ensure you're copying from the correct Service Key fields (`url` and `uaa.url`).
3. **Different subdomains**: Remember that these URLs are on different subdomains and cannot be derived from each other.
