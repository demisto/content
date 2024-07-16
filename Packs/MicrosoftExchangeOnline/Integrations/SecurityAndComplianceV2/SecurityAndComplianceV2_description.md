# O365 - Security And Compliance - Content Search V2

This integration enables you to manage the features that are available in the Security & Compliance Center from XSOAR.

For this integration, the UPN/Email is the account you wish to use in order to interface with Security & Compliance. 
The account may require additional permissions and roles associated with it in order to execute all commands. 
Please refer to the [documentation](https://xsoar.pan.dev/docs/reference/integrations/security-and-compliance-v2#authentication) for additional information.

Supported authentication methods:
- OAuth2.0 (For MFA enabled accounts) -
    1. Fill in the UPN parameter in the integration configuration.
    2. Run the ***o365-sc-auth-start*** command and follow the instructions.
    3. For testing completion of authorization process run the ***o365-sc-auth-test*** command.

## Security and Compliance Integration Changes

### Overview
In response to Microsoft's deprecation of the App ID, the following changes to app registration in Azure are required:
1. Add the `Exchange.Manage` delegated permissions.
2. Enable "Allow public client flows" in the authentication section.
3. Add an app secret to the app registration.

### Step-by-Step Instructions

#### 1. Add Exchange.Manage Delegated Permissions

1. **Navigate to Azure Portal:**
   Go to the [Azure Portal](https://portal.azure.com/) and sign in with your administrator account.

2. **Access App Registrations:**
   In the left-hand navigation pane, select **Azure Active Directory**. Then, under **Manage**, select **App registrations**.

3. **Select Your App:**
   Find and select the app registration you are working on.

4. **Add Permissions:**
   - Under **Manage**, select **API permissions**.
   - Click on **Add a permission**.
   - Select **APIs my organization uses**.
   - Type "Office" in the search bar and select **Office 365 Exchange Online**.
   - Choose **Delegated permissions**.
   - Search for `Exchange.Manage` and check the corresponding box.
   - Click on **Add permissions**.
   - Ensure the permissions are granted for your organization by selecting **Grant admin consent for [Your Organization]** and confirming the action.

#### 2. Enable "Allow Public Client Flows"

1. **Navigate to Authentication Settings:**
   From your app registration, under **Manage**, select **Authentication**.

2. **Enable Public Client Flows:**
   - Scroll down to the **Advanced settings** section.
   - Locate the setting **Allow public client flows** and set it to **Yes**.
   - Click **Save** at the top to apply the changes.

#### 3. Add an App Secret

1. **Navigate to Certificates & Secrets:**
   From your app registration, under **Manage**, select **Certificates & secrets**.

2. **Add a Client Secret:**
   - Click on **New client secret**.
   - Provide a description for the client secret.
   - Choose an expiration period that meets your organization's security policy.
   - Click **Add**.
   - After the secret is created, copy the value immediately as it will not be displayed again. Store this secret securely, as it will be used in your application to authenticate.


### Additional Resources
- [Azure Active Directory App Registrations](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [API Permissions in Microsoft Graph](https://docs.microsoft.com/en-us/graph/permissions-reference)
- [Configure Authentication in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [Add a Client Secret](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#option-2-create-a-new-application-secret)

These steps will ensure your app registration is updated correctly to maintain the necessary functionality after Microsoft's deprecation of the App ID. If you have any questions or run into issues, please refer to the provided documentation links or contact your Azure support team.