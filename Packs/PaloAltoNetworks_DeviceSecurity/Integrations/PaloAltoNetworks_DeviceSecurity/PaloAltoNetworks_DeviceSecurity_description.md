## Palo Alto Networks Device Security

### Required Permissions
Use a service account with the minimum permissions below:

| Resource | Permissions |
| --- | --- |
| Devices | Read |
| Alerts | Read, Write |
| Vulnerabilities | Read, Write |

### Get your Palo Alto Networks Device Security Credentials
This integration requires API access configuration.

To obtain the **Client ID** and **Client Secret**, see the [API User Guide](https://pan.dev/iot/api/iot-public-api-new).

### Obtain the Required Credentials

Before configuring the integration, obtain the following from your Strata Cloud Manager (SCM) tenant:

- Tenant Service Group (TSG) ID
- OAuth Client ID
- OAuth Client Secret

### 1. Sign in to Strata Cloud Manager

1. Open the SCM portal: `https://stratacloudmanager.paloaltonetworks.com`
2. Sign in using your SSO account and complete the required authentication (Security Key, Biometric Authenticator, or Okta FastPass).
3. Click your **Profile** in the lower-left corner.
4. Select the required tenant and click the **blue arrow** to switch to it.
5. Verify that the selected tenant appears under **Currently viewing**.

### 2. Create a Custom Role

1. Search for **Identity & Access Management** and open the **System Settings** page.
2. Select the **Roles** tab.
3. Open the **Custom Roles** tab and click **Add Custom Role**.
4. Enter a **Name**, **Display Name**, and **Description**.
5. Under **Device Security**, assign the following permissions:
   - **Devices** → Read
   - **Alerts** → Read, Write
   - **Vulnerabilities** → Read, Write
6. Click **Save**.
7. Verify that the custom role appears in the **Custom Roles** list.

### 3. Create a Service Account

1. Open the **Access Management** tab.
2. Click **Add Identity**.
3. Select **Service Account** as the identity type.
4. Enter a **Service Account Name** and click **Next**.
5. Copy or download the generated **Client ID** and **Client Secret** (for example, by downloading the CSV file). Store the credentials securely, as the Client Secret may not be displayed again.
6. Click **Next**.
7. Configure the service account:
   - **Apps & Services:** **Device Security**
   - **Role:** Select the custom role created earlier.
   - **Scope:** Leave as **All resources**, unless a different scope is required.
8. Click **Submit**.
9. Verify that the service account appears under **All Service Accounts**.

### 4. Configure the Integration

Use the following values when creating the integration instance in Cortex XSOAR:

- **TSG ID**
- **Client ID**
- **Client Secret**