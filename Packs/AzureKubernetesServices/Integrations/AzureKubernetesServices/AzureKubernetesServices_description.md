# Self-Deployed Application
To use a self-configured Azure application, you need to add a [new Azure App Registration in the Azure Portal](https://docs.microsoft.com/en-us/graph/auth-register-app-v2#register-a-new-application-using-the-azure-portal).

* The application must have **user_impersonation** permission (can be found in *API permissions* section of the Azure Kubernetes Services app registrations).
* The application must allow **public client flows** (can be found under the *Authentication* section of the Azure Kubernetes Services app registrations).
* The application must allow public client flows (found under the **Authentication** section of the app) for Device-code based authentications.

In case you want to use Device code flow, you must allow public client flows (can be found under the **Authentication** section of the app).

### Authentication Using the User - Authentication Flow (recommended)

Follow these steps for User - Authentication configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. choose the user_auth_flow option in the ***Authentication Type*** parameter.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Client Secret*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.
6. Enter your Application redirect URI in the ***Application redirect URI*** parameter.
7. Save the instance.
8. Run the `!azure-ks-generate-login-url` command in the War Room and follow the instruction.
9. Run the ***!azure-ks-auth-test*** command - a 'Success' message should be printed to the War Room.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (ab217a43-e09b-4f80-ae93-482fc7a3d1a3).

### Authentication Using the Device Code Flow
Follow these steps for a self-deployed configuration:

1. Fill in the required parameters.
2. choose the 'Device' option in the ***user_auth_flow*** parameter.
3. Run the ***!azure-ks-auth-start*** command. 
4. Follow the instructions that appear.
5. Run the ***!azure-ks-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - In the **Authentication Type** drop-down list, select **Azure Managed Identities** and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities client ID** field in the instance configuration.
   3. In the **Authentication Type** drop-down list, select **Azure Managed Identities**.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).
