### Deprecation Note: 
`Fetch incidents` is deprecated. Use the `Microsoft Graph Security` integration instead in order to fetch incidents.

# Authentication

You can use the following methods to authenticate Microsoft Defender for Endpoint:

1. Cortex XSOAR app
2. Authorization Code Flow
3. Client Credentials Flow
4. Azure Managed Identities

### Authentication Using Cortex XSOAR app

To use the **Cortex XSOAR application** and allow Cortex XSOAR/XSIAM access to Microsoft Defender For Endpoint an administrator has to approve our app using an admin consent flow by clicking this **[link](https://oproxy.demisto.ninja/ms-defender-atp)**.
After authorizing the Cortex XSOAR app, you will get an ID, Token, and Key which should be inserted in the integration instance settings fields.
If you previously had an API V1 configured based on the credentials obtained from this method, refer to the link above to gain new credentials with the relevant permissions.

For more information, refer to this [documentation](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application).

### Authentication Using Authorization Code Flow

Use the [authorization code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows:~:text=then%20click%20%22Test%22.-,Authorization%20Code%20flow%23,-Some%20Cortex%20XSOAR)
to link Microsoft Defender For Endpoint with Cortex XSOAR/XSIAM.

For this flow you must use a self-deployed application. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
For more details, follow [Self Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application:~:text=Self%20Deployed%20Application%23).

After you created a self-deployed application, follow these steps:

1. In your app, click **Authentication** -> **Platform configurations** -> **Add a platform**. Choose Web and add a Redirect URI. The Redirect URI is the address where Azure AD sends the login response. If you are not sure what to set, you can use https://localhost. 
2. Enter your redirect URI in the **Redirect URI** parameter field in the instance configuration in XSOAR/XSIAM. 
3. Go to "Overview" section. Copy the "Application (client) ID" and paste it in the **Application ID or Client ID** parameter field in the instance configuration in XSOAR/XSIAM. 
4. Copy the "Directory (tenant) ID" and paste it in the **Token or Tenant ID** parameter field in the instance configuration in XSOAR/XSIAM. 
5. In the application configuration go to "Certificates & secrets", click "New client secret", then "Add". Copy the secret value and paste it under the **Key or Client Secret** parameter field in the XSOAR/XSIAM instance configuration. 
6. Select the **Use a self-deployed Azure application** checkbox in the integration instance configuration. 
7. Save the instance. 
8. Run the !msg-generate-login-url command in the War Room and follow these instructions:
9. Click the login URL to sign in and grant Cortex XSOAR/XSIAM permissions to access your Azure Service Management. You will be automatically redirected to a link with the following structure:
   ```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE``` 
10. Copy the AUTH_CODE (between the code= prefix and the session_state prefix) and paste it in your instance configuration under the **Authorization Code** parameter. 
11. Save the instance.
12. Run the !msg-auth-test command. The War Room prints a 'Success' message if the integration is configured correctly.


### Authentication Using Client Credentials Flow

Use the [client credentials flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows:~:text=Client%20Credentials%20Flow%23)
to link Microsoft Defender For Endpoint with Cortex XSOAR/XSIAM.

For this flow you must use a self-deployed application. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
For more details, follow [Self Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application:~:text=Self%20Deployed%20Application%23).

After you created a self-deployed application, follow these steps:

1. Sign in to the Azure Portal and search for you application using your application name or ID. You can find it under the "App registrations" or use the search bar.
2. When you locate the application, click it and go to the **Overview** section.
3. Copy the "Application (client) ID" and paste it in the **App/Client ID** parameter field in the XSOAR/XSIAM instance configuration.
4. Copy the "Directory (tenant) ID" and paste it in the **Token/Tenant ID** parameter field in the XSOAR/XSIAM instance configuration.
5. In the application configuration, go to "Certificates & secrets", click "New client secret", then click "Add". Copy the secret value and paste it into the **Client Secret** parameter field in the XSOAR/XSIAM instance configuration.
6. In the instance configuration, select the Use a self-deployed Azure Application checkbox.
7. Test and Save the instance.


## Azure Managed Identities

**Note**: This option is relevant only if the integration is running on Azure VM.

Follow one of these steps for authentication based on Azure Managed Identities:

#### To use System Assigned Managed Identity

- Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

#### To use User Assigned Managed Identity

- Go to [Azure Portal](https://portal.azure.com/) > **Managed Identities**.
- Select your **User Assigned Managed Identity**, copy the client ID, and paste it in the integration instance settings **Azure Managed Identities Client ID** field.
- Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
