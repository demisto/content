# O365 - Security And Compliance - Content Search V2

This integration enables you to manage the features that are available in the Security & Compliance Center from XSOAR.

For this integration, the UPN/Email is the account you wish to use in order to interface with Security & Compliance. 
The account may require additional permissions and roles associated with it in order to execute all commands. 
Please refer to the [documentation](https://xsoar.pan.dev/docs/reference/integrations/security-and-compliance-v2#authentication) for additional information.

Supported authentication methods:
- App-only (OAuth2.0) Authentication -
    1. Fill in the UPN, App ID, and Tenant ID parameters in the integration configuration.
    2. Run the ***o365-sc-auth-start*** command and follow the instructions.
    3. For testing completion of authorization process run the ***o365-sc-auth-test*** command.
- Delegated User Authentication -
    1. Fill in the UPN parameter in the integration configuration.
    2. Add the user’s Microsoft 365 password (the regular sign-in password for that UPN).
    3. For testing completion of authorization process run the ***o365-sc-auth-test*** command.

**Note: If a UPN password is provided**  
- Even if the password is incorrect, the integration will attempt to authenticate using it.
- In this case, all connections to Microsoft Security and Compliance PowerShell will use interactive delegated authentication.


## App-only (OAuth2.0) Authentication Changes

### Overview
In response to Microsoft's deprecation of the App ID, the following changes to app registration in Azure are required:
1. Add the `Exchange.Manage` delegated permissions.
2. Enable "Allow public client flows" in the authentication section.

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


### Additional Resources
- [Azure Active Directory App Registrations](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [API Permissions in Microsoft Graph](https://docs.microsoft.com/en-us/graph/permissions-reference)
- [Configure Authentication in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [Add a Client Secret](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#option-2-create-a-new-application-secret)

These steps will ensure your app registration is updated correctly to maintain the necessary functionality. If you have any questions or run into issues, please refer to the provided documentation links or contact your Azure support team.

## Delegated User Authentication

### Overview

In this mode, the integration connects using a user’s UPN (email) and Microsoft 365 password.  Actions are performed under that user’s permissions within the Security & Compliance Center.
Before using this method, verify that your account allows password-only sign-in (MFA must be disabled).

#### Verify that your account does not require multi-factor authentication (MFA):
1. Go to the [Microsoft 365 Admin Center](https://admin.microsoft.com/) and sign in with your administrator account.
2. Under **Users**, select **Active users**.
3. At the top, click Multi-factor authentication.
4. In the list that appears, find your user and check the Multi-Factor Auth Status column is disabled.