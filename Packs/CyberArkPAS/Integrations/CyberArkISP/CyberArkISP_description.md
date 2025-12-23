## CyberArk Identity Security Platform

This integration collects audit events from CyberArk Identity Security Platform (ISP) for security monitoring and compliance purposes.

### How to Configure the Integration Instance

Follow these steps to configure the CyberArk Identity Security Platform integration:

## Authentication and Authorization

The integration uses OAuth2 Client Credentials flow with API key authentication. You must complete the following three steps in CyberArk Identity Administration before configuring the integration:

### Step 1: Create and Configure an OAuth2 Server Web App in Identity Administration

1. In Identity Administration, go to **Apps & Widgets** > **Web Apps**, and click **Add Web Apps**.
2. In the Add Web Apps dialog, click the **Custom** tab, locate the **OAuth2 Server** web app, and click **Add**.
3. Click **Yes** to add the web app.
4. In the Web Apps page, select the **OAuth2 Server** app that you just added.
5. In the OAuth2 Server page, configure the following:
   - **Settings tab**: In the **Application ID** field, enter a name for this web app (e.g., `xsiamapp`). This will be your **Web App ID**.
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

## Configuration Parameters

| **Parameter** | **Description** | **Example** |
| --- | --- | --- |
| Identity URL | CyberArk Identity FQDN for OAuth2 authentication | `https://abc1234.id.cyberark.cloud` |
| Audit Server URL | Audit API base URL from the SIEM integration | `https://example-domain.audit.cyberark.cloud` |
| Web App ID | Application ID of the OAuth2 Server web app configured in Step 1 | `xsiamapp` |
| Client ID | Service username without domain (from Step 2) | `serviceuser` |
| Client Secret | Service user password (from Step 2) | `********` |
| API Key | API key from the SIEM integration (from Step 4) | `********` |

## Additional Resources

For more information about CyberArk Identity Security Platform integration, refer to the official CyberArk documentation:

- [Integrate Audit with third-party SIEM applications](https://docs.cyberark.com/identity/latest/en/Content/Integrations/SIEM/SIEM-intro.htm)
- [SIEM Integration API](https://docs.cyberark.com/identity/latest/en/Content/Developer/SIEM-API.htm)
- [Integrate the CyberArk Identity client credentials flow](https://docs.cyberark.com/identity/latest/en/Content/Developer/OAuth-client-creds.htm)
