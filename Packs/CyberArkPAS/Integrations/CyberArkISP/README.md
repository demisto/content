# CyberArk Identity Security Platform

## Overview

The CyberArk Identity Security Platform is a unified solution securing all human and machine identities (workforce, customers, non-human) across hybrid/multi-cloud environments, centered on intelligent privilege controls, AI-driven threat detection (CORA AI), and lifecycle automation to enforce least privilege and Zero Trust, providing a single portal for access management, PAM, and endpoint security.

This integration collects audit events from CyberArk Identity Security Platform for security monitoring and compliance purposes in your Cortex environment.

## Authentication

This integration uses OAuth2 Client Credentials flow combined with API key authentication for secure access to the CyberArk Identity Security Platform Audit API.

### Authentication Flow

1. **OAuth2 Token Generation**: The integration obtains an access token from the CyberArk Identity service using client credentials (Client ID and Client Secret).
2. **API Authentication**: The access token is combined with an API key to authenticate requests to the Audit API.
3. **Token Caching**: Access tokens are cached and automatically refreshed when expired to optimize performance.

### Security Features

- **Automatic Token Refresh**: Tokens are automatically refreshed before expiration
- **Secure Credential Storage**: All credentials are securely stored in Cortex
- **Telemetry Tracking**: Integration usage is tracked via telemetry headers for monitoring and analytics

## CyberArk ISP Architecture

CyberArk Identity Security Platform uses **two separate services** for different purposes:

1. **Identity Service** (OAuth2 Authentication): Used for generating access tokens
   - Example: `https://aca4372.id.cyberark.cloud`
   - Used to construct Token URL: `https://aca4372.id.cyberark.cloud/OAuth2/Token/{WEB_APP_ID}`

2. **Audit Service** (Audit API): Used for fetching audit events
   - Example: `https://panw-demo-eu-central-1.audit.cyberark.cloud`
   - API Endpoints:
     - `/api/audits/stream/createQuery` - Create a stream query
     - `/api/audits/stream/results` - Retrieve paginated results

**Important**: These services are on different domains and must be configured separately for the integration to work correctly.

## Before You Start

Before configuring the integration, you must complete the following prerequisites in your CyberArk Identity Administration:

### Step 1: Create and Configure an OAuth2 Server Web App in Identity Administration

1. In Identity Administration, go to **Apps & Widgets** > **Web Apps**, and click **Add Web Apps**.
2. In the Add Web Apps dialog, click the **Custom** tab, locate the **OAuth2 Server** web app, and click **Add**.
3. Click **Yes** to add the web app.
4. In the Web Apps page, select the **OAuth2 Server** app that you just added.
5. In the OAuth2 Server page, configure the following:
   - **Settings tab**: In the **Application ID** field, enter a name for this web app (e.g., `xsiamauditapp`). This will be your **Web App ID**.
   - **Tokens tab**: In the **Token Type** field, select **jwtRS256**. Under **Auth methods**, ensure that the **Client Creds** authentication method is selected.
   - **Scope tab**: Click **Add**, copy and paste the following text in the **Name** field, and then click **Save**:

     ```
     isp.audit.events:read
     ```

   - **Advanced tab**: Copy and paste the following script:

     ```javascript
     setClaim('tenant_id', TenantData.Get("CybrTenantID"));
     setClaim('aud', 'cyberark.isp.audit');
     ```

### Step 2: Create a Service User in Identity Administration

1. Go to **Core Services** > **Users**, and click **Add User**.
2. In the Create CyberArk Cloud Directory User page, enter the information in the required fields.
3. In the **Status** area, select **is OAuth confidential client**, and then click **Create User**.
4. In the Users page, select the **All Service Users** set, and then locate and select the user that you just created.
5. In the User details page, select the **Application Settings** tab and then click **Add**.
6. Locate and select the OAuth2 Server web app, and click **Save**.
7. Enter your user name, and click **OK**.

**Note**: The service username (without domain) will be your **Client ID**, and the service password will be your **Client Secret**.

### Step 3: Set the Service User Permissions in Identity Administration

1. Go to **Apps & Widgets** > **Web Apps**, and select the OAuth2 Server web app that you added.
2. Select the **Permissions** tab, locate the service user that you created, and select the following permissions:
   - Grant
   - View
   - Run
   - Automatically Deploy
3. Click **Save**.

### Step 4: Add a SIEM Integration in the Administration Space

1. Go to the **Administration** space.
2. Select **My environment** > **Integrations** > **Export to SIEM**.
3. Click **Create**, and select **Create SIEM integration**.
4. Enter a name for the SIEM integration and an optional description.
5. Click **Apply**. An **API key** is created.
6. Copy the **API key** and the **API base URL** for use in the integration configuration.

**Important**: You can only have two third-party SIEM integrations. If you want to add an integration, you must delete one of the existing integrations.

## Configure CyberArk Identity Security Platform in Cortex

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**
2. Search for CyberArk Identity Security Platform.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Audit Server URL (Audit API Base URL) | The Audit API base URL from the SIEM integration.<br/>Example: `https://panw-demo-eu-central-1.audit.cyberark.cloud`<br/>**Note**: This is different from the Identity URL. | True |
| Identity URL (CyberArk Identity FQDN) | The CyberArk Identity FQDN for OAuth2 authentication.<br/>Example: `https://aca4372.id.cyberark.cloud`<br/>**Important**: This is on a different domain than the Audit Server URL and is required. | True |
| OAuth2 Web App ID | The Application ID of the OAuth2 Server web app configured in Identity Administration.<br/>Example: `xsiamauditapp` | True |
| Client ID (Service User) | Service username without domain (configured as OAuth confidential client).<br/>Example: `serviceuser` | True |
| Client Secret (Service User Password) | Service user password for OAuth2 authentication. | True |
| API Key | The API key from the SIEM integration created in the Administration space. | True |
| Trust any certificate (not secure) | When selected, the integration will not verify SSL certificates. | False |
| Use system proxy settings | When selected, the integration will use the system proxy settings. | False |
| Maximum number of audit events per fetch | Maximum number of events to fetch per collection cycle.<br/>Default: 10000<br/>Note: The API returns a maximum of 1000 events per page. | False |

4. Click **Test** to validate the connection and authentication.
5. Click **Done** to save the integration instance.

## How It Works

This integration automatically collects audit events from CyberArk Identity Security Platform and sends them to your Cortex environment for security monitoring and compliance.

1. **Initial Collection**: On the first run, the integration begins collecting events from 1 minute ago.
2. **Continuous Monitoring**: The integration automatically tracks the last collected event timestamp and fetches only new events on subsequent runs.
3. **Automatic Pagination**: The integration handles large result sets automatically, retrieving up to the configured maximum number of events per collection cycle.
4. **Deduplication**: Events are deduplicated based on their UUID to prevent duplicate ingestion.
5. **Timestamp Tracking**: The integration maintains a high-water mark timestamp and UUIDs to ensure no events are missed or duplicated.

### Event Collection Process

1. **Create Query**: The integration creates a stream query with a date range filter
2. **Fetch Pages**: Results are fetched page by page using cursor-based pagination
3. **Deduplicate**: Events are checked against previously fetched UUIDs
4. **Ingest**: New events are sent to XSIAM with the `_time` field mapped from the event's `timestamp`

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberark-isp-get-events

***
Gets audit events from CyberArk Identity Security Platform. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and API request limitation exceeding.

**Note**: This command is not supported in XSOAR.

#### Base Command

`cyberark-isp-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_from | The start date/time to fetch events from (format: YYYY-MM-DD HH:MM:SS). Supports relative time (e.g., "3 days ago", "2 hours ago") or specific absolute dates (e.g., "2025-09-15 17:10:00"). Default is "1 minute ago". | Optional |
| date_to | The end date/time to fetch events until (format: YYYY-MM-DD HH:MM:SS). Supports relative time (e.g., "1 hour ago", "now") or specific absolute dates (e.g., "2025-09-15 17:11:00"). If not specified, fetches until now. | Optional |
| limit | Maximum number of events to retrieve. Default is 50. | Optional |
| should_push_events | Set to true to push events to XSIAM (use with caution to avoid duplicates), false to only return them in the War Room. Default is false. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkISP.Event.uuid | String | Unique identifier of the audit event. |
| CyberArkISP.Event.tenantId | String | Tenant identifier. |
| CyberArkISP.Event.timestamp | Number | Event timestamp (Unix milliseconds). |
| CyberArkISP.Event.username | String | Username associated with the event. |
| CyberArkISP.Event.applicationCode | String | Application code (e.g., IDP). |
| CyberArkISP.Event.auditCode | String | Audit code identifier. |
| CyberArkISP.Event.auditType | String | Type of audit event (e.g., Info, Warning, Error). |
| CyberArkISP.Event.action | String | Action performed. |
| CyberArkISP.Event.userId | String | User ID associated with the event. |
| CyberArkISP.Event.source | String | Source IP address. |
| CyberArkISP.Event.actionType | String | Type of action (e.g., Start, End). |
| CyberArkISP.Event.component | String | Component name. |
| CyberArkISP.Event.serviceName | String | Service name. |
| CyberArkISP.Event.message | String | Event message. |
| CyberArkISP.Event.customData | Unknown | Custom event data. |
| CyberArkISP.Event.cloudProvider | String | Cloud provider (e.g., aws). |
| CyberArkISP.Event.identityType | String | Identity type (e.g., NON_HUMAN, HUMAN). |
| CyberArkISP.Event.originRegion | String | Origin region. |

#### Command Example

```
!cyberark-isp-get-events date_from="3 days ago" limit=50
```

```
!cyberark-isp-get-events date_from="2025-09-15 17:10:00" date_to="2025-09-15 17:11:00" limit=100
```

```
!cyberark-isp-get-events date_from="1 hour ago" limit=10 should_push_events=false
```

#### Human Readable Output

>### CyberArk Identity Security Platform Events
>
>|uuid|tenantId|timestamp|username|applicationCode|auditCode|action|
>|---|---|---|---|---|---|---|
>| a83ca203-e98c-43b1-9f77-593c4cc40980 | 70851320-117b-4c4d-810f-7bd41e3f1829 | 1758953765835 | SYSTEM$ | IDP | IDP1301 | Outbound provisioning sync initiated |
>| b9bde171-79cd-48d4-8c13-88eecda90abd | 70851320-117b-4c4d-810f-7bd41e3f1829 | 1758953765835 | SYSTEM$ | IDP | IDP1302 | Outbound provisioning sync completed |

## API Documentation

The integration uses the following CyberArk Identity Security Platform APIs:

### 1. OAuth2 Token API

**Endpoint**: `POST https://{identity_fqdn}/OAuth2/Token/{WEB_APP_ID}`

**Purpose**: Generate access tokens for API authentication

**Request Example**:

```http
POST /oauth2/token/xsiamauditapp
Host: aca4372.id.cyberark.cloud
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<client_id>&client_secret=<client_secret>&scope=isp.audit.events%3Aread
```

**Response Example**:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 21600
}
```

### 2. Create Stream Query API

**Endpoint**: `POST /api/audits/stream/createQuery`

**Purpose**: Create a query to stream audit events

**Headers**:

- `Authorization: Bearer {access_token}`
- `x-api-key: {api_key}`
- `x-cybr-telemetry: {base64_encoded_telemetry}`
- `Content-Type: application/json`

**Request Example**:

```json
{
  "filterModel": {
    "dateFrom": "2025-09-15 17:10:00",
    "dateTo": "2025-09-15 17:11:00"
  },
  "sortModel": [
    {
      "field_name": "timestamp",
      "direction": "asc"
    }
  ]
}
```

**Response Example**:

```json
{
  "cursorRef": "eyJxdWVyeSI6eyJwYWdlU2l6ZSI6MTAwMCwic2VsZWN0ZWRGaWVsZHMiOls..."
}
```

### 3. Stream Results API

**Endpoint**: `POST /api/audits/stream/results`

**Purpose**: Retrieve paginated audit events using cursor reference

**Request Example**:

```json
{
  "cursorRef": "eyJxdWVyeSI6eyJwYWdlU2l6ZSI6MTAwMCwic2VsZWN0ZWRGaWVsZHMiOls..."
}
```

**Response Example**:

```json
{
  "data": [
    {
      "uuid": "a83ca203-e98c-43b1-9f77-593c4cc40980",
      "tenantId": "70851320-117b-4c4d-810f-7bd41e3f1829",
      "timestamp": 1758953765835,
      "username": "SYSTEM$",
      "applicationCode": "IDP",
      "auditCode": "IDP1301",
      "auditType": "Info",
      "action": "Outbound provisioning sync initiated",
      "customData": {...}
    }
  ],
  "paging": {
    "cursor": {
      "cursorRef": "eyJxdWVyeSI6eyJwYWdlU2l6ZSI6MTAwMCwic2VsZWN0ZWRGaWVsZHMiOls..."
    }
  }
}
```

## Telemetry

The integration includes telemetry headers in all API requests to provide CyberArk with insights into integration usage:

**Header**: `x-cybr-telemetry`

**Value** (base64 encoded):

```
in=CyberArk Identity Security Platform&it=SIEM&iv=1.0&vn=Palo Alto Networks&VV=3.x
```

**Fields**:

- `in`: Integration Name
- `it`: Integration Type (SIEM)
- `iv`: Integration Version
- `vn`: Vendor Name
- `VV`: Vendor Version

## Additional Resources

For more information about CyberArk Identity Security Platform integration, refer to the official CyberArk documentation:

- [Integrate Audit with third-party SIEM applications](https://docs.cyberark.com/identity/latest/en/Content/Integrations/SIEM/SIEM-intro.htm)
- [SIEM Integration API](https://docs.cyberark.com/identity/latest/en/Content/Developer/SIEM-API.htm)
- [Integrate the CyberArk Identity client credentials flow](https://docs.cyberark.com/identity/latest/en/Content/Developer/OAuth-client-creds.htm)

## Best Practices

1. **Use Exact URLs**: Copy the exact URLs from your CyberArk environment:
   - Identity URL from your Identity tenant
   - Audit Server URL from the SIEM integration
2. **Verify Both URLs**: Ensure both Identity URL and Audit Server URL are on their correct domains (different from each other).
3. **Secure Credential Storage**: Ensure that authentication credentials (Client Secret and API Key) are stored securely.
4. **Configure Appropriate Limits**: Set the maximum number of events per fetch based on your organization's event volume (default: 10000).
5. **Monitor Token Usage**: The integration automatically manages token lifecycle, but monitor for any authentication errors.
6. **Test Before Production**: Use the `cyberark-isp-get-events` command with `should_push_events=false` to test event retrieval before enabling automatic collection.

## Troubleshooting

### 401 Unauthorized Error

If you receive a 401 Unauthorized error, verify:

1. **Client Credentials are correct**: Ensure your Client ID and Client Secret match the service user created in Identity Administration.
2. **Service User has OAuth confidential client enabled**: Verify the service user is configured as an OAuth confidential client.
3. **Web App ID is correct**: Ensure the Web App ID matches the Application ID configured in the OAuth2 Server web app.
4. **Scope is configured**: Verify the scope `isp.audit.events:read` is added to the OAuth2 Server web app.

### 403 Forbidden Error

If you receive a 403 error:

1. **Check Service User Permissions**: Ensure the service user has Grant, View, Run, and Automatically Deploy permissions on the OAuth2 Server web app.
2. **Verify API Key**: Ensure the API Key is correct and copied from the SIEM integration in the Administration space.

### 404 Not Found Error

If you receive a 404 error:

1. **Check URLs**: Verify both the Identity URL and Audit Server URL are correct and accessible.
2. **Verify SIEM Integration**: Ensure the SIEM integration is created and active in the Administration space.
3. **Check Web App ID**: Verify the Web App ID exists and is correctly configured.

### No Events Retrieved

If no events are being retrieved:

1. **Check Date Range**: Ensure the date range includes periods with audit activity.
2. **Verify Event Generation**: Check that audit events are being generated in your CyberArk environment.
3. **Review Filters**: Ensure no filters are preventing event retrieval.
4. **Check Limits**: Verify the maximum events limit is appropriate for your environment.

### Duplicate Events

If you're seeing duplicate events:

1. **Avoid Manual Commands**: Don't use `cyberark-isp-get-events` with `should_push_events=true` while automatic fetch is enabled.
2. **Check Multiple Instances**: Ensure you don't have multiple integration instances fetching the same events.
3. **Review Deduplication**: The integration uses UUID-based deduplication; verify events have unique UUIDs.
