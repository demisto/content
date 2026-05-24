<~XSIAM>

## What does this pack do?

## Overview

The **CyberArk Identity Security Platform** is a unified solution that secures all human and machine identities (workforce, customers, non-human) across hybrid and multi-cloud environments. It is centered on intelligent privilege controls, AI-driven threat detection (CORA AI), and lifecycle automation to enforce least privilege and Zero Trust, providing a single portal for access management, PAM, and endpoint security.

This pack enables ingestion and normalization of CyberArk Identity Security Platform audit events into Cortex XSIAM for security monitoring and compliance.

## This pack includes

Data normalization capabilities:

* Modeling Rules for CyberArk Identity Security Platform audit events that are ingested via the CyberArk ISP integration into Cortex XSIAM.
* The ingested CyberArk Identity audit events can be queried in XQL Search using the *`cyberark_isp_raw`* dataset.

## Supported event categories

The pack normalizes two primary categories of CyberArk Identity audit events:

| Category        | Description                                                                                          | Classification field(s)                                                  |
|:----------------|:-----------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------|
| Authentication  | Login, MFA challenge/response, OAuth token issuance, impersonation, SAML, and other auth events.     | `message in (cloud.core.*)` **or** `auditCode` in the AUTH list.         |
| SaaS Audit      | Application/role/policy/device/user lifecycle and configuration changes performed in the platform.   | `auditCode` in the SAAS list (e.g., `IDP2001`, `IDP6001`, `IDP1707`...). |

### Supported timestamp format

* Epoch milliseconds as a string: `"1776674727346"`

***

## Data Collection

### CyberArk Identity Security Platform side

This pack consumes audit events that are pulled from the **CyberArk Identity Security Platform Audit API** via OAuth2 Client Credentials flow combined with API key authentication.

Before configuring the integration in Cortex XSIAM, complete the following prerequisites in **CyberArk Identity Administration**.

#### Step 1 — Create and configure an OAuth2 Server Web App

1. In **Identity Administration**, go to **Apps & Widgets** → **Web Apps** and click **Add Web Apps**.
2. In the **Add Web Apps** dialog, click the **Custom** tab, locate the **OAuth2 Server** web app, and click **Add**.
3. Click **Yes** to add the web app.
4. In the **Web Apps** page, select the OAuth2 Server app you just added and configure:
    * **Settings tab** → In **Application ID**, enter a name for the web app (e.g., `xsiamapp`). This is your **Web App ID**.
    * **Tokens tab** → Set **Token Type** to `jwtRS256`. Under **Auth methods**, ensure **Client Creds** is selected.
    * **Scope tab** → Click **Add**, enter the following name, and click **Save**:

      ```
      isp.audit.events:read
      ```

    * **Advanced tab** → Paste the following script:

      ```
      setClaim('tenant_id', TenantData.Get("CybrTenantID"));
      setClaim('aud', 'cyberark.isp.audit');
      ```

#### Step 2 — Create a Service User

1. Go to **Core Services** → **Users** and click **Add User**.
2. In the **Create CyberArk Cloud Directory User** page, fill in the required fields.
3. In the **Status** area, select **is OAuth confidential client**, then click **Create User**.
4. In the **Users** page, select the **All Service Users** set and select the user you just created.
5. In the **User details** page, select the **Application Settings** tab and click **Add**.
6. Locate and select the **OAuth2 Server** web app, and click **Save**.
7. Enter your user name and click **OK**.

> **Note:** The service username (without domain) is your **Client ID**, and the service password is your **Client Secret**.

#### Step 3 — Set the Service User Permissions

1. Go to **Apps & Widgets** → **Web Apps** and select the OAuth2 Server web app.
2. Select the **Permissions** tab, locate the service user you created, and grant the following:
    * Grant
    * View
    * Run
    * Automatically Deploy
3. Click **Save**.

#### Step 4 — Add a SIEM Integration in the Administration Space

1. Go to the **Administration** space.
2. Select **My environment** → **Integrations** → **Export to SIEM**.
3. Click **Create**, then **Create SIEM integration**.
4. Enter a name and an optional description for the SIEM integration.
5. Click **Apply**. An **API key** is created.
6. Copy the **API key** and the **API base URL** for use in the Cortex XSIAM integration.

> **Important:** You can have at most two third-party SIEM integrations. To add a new one, you must delete an existing one.

***

### Cortex XSIAM side — CyberArk ISP integration

Configure the **CyberArk Identity Security Platform** integration in Cortex XSIAM using the credentials and endpoints captured above.

| Parameter                                  | Description                                                                                                                                                                       | Required |
|:-------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------|
| `Audit Server URL` (Audit API Base URL)    | The Audit API base URL from the SIEM integration. Example: `https://example-domain.audit.cyberark.cloud`. Note: this is **different** from the Identity URL.                      | True     |
| `Identity URL` (CyberArk Identity FQDN)    | The CyberArk Identity FQDN used for OAuth2 authentication. Example: `https://abc1234.id.cyberark.cloud`. **Important:** this is on a different domain than the Audit Server URL.  | True     |
| `OAuth2 Web App ID`                        | The Application ID of the OAuth2 Server web app configured in Identity Administration. Example: `xsiamapp`.                                                                       | True     |
| `Client ID` (Service User)                 | Service username **without** domain (configured as OAuth confidential client). Example: `serviceuser`.                                                                            | True     |
| `Client Secret` (Service User Password)    | Service user password used for OAuth2 authentication.                                                                                                                             | True     |
| `API Key`                                  | The API key created in the Administration space when adding the SIEM integration.                                                                                                 | True     |
| `Trust any certificate (not secure)`       | When selected, the integration will not verify SSL certificates.                                                                                                                  | False    |
| `Use system proxy settings`                | When selected, the integration will use the system proxy settings.                                                                                                                | False    |
| `Maximum number of audit events per fetch` | Maximum number of events to fetch per collection cycle. Default: `10000`. The API returns at most 1000 events per page.                                                           | False    |

#### Inputs

| Argument Name        | Description                                                                                                                                                                                                                | Required |
|:---------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------|
| `date_from`          | Start date/time to fetch events from (format: `YYYY-MM-DD HH:MM:SS`). Supports relative time (e.g., `"3 days ago"`, `"2 hours ago"`) or specific absolute dates (e.g., `"2025-09-15 17:10:00"`). Default: `"1 minute ago"`. | Optional |
| `date_to`            | End date/time to fetch events until (format: `YYYY-MM-DD HH:MM:SS`). Supports relative time or absolute dates. If not specified, fetches until now.                                                                        | Optional |
| `limit`              | Maximum number of events to retrieve. Default: `50`.                                                                                                                                                                       | Optional |
| `should_push_events` | `true` to push events into XSIAM (use with caution to avoid duplicates), `false` to only return them in the War Room. Default: `false`. Possible values: `true`, `false`.                                                  | Optional |

</~XSIAM>
