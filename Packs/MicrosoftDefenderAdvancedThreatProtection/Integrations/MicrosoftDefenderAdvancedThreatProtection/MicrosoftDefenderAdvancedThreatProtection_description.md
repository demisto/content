### Deprecation Note: 
`Fetch incidents` is deprecated. Use the `Microsoft Graph Security` integration instead in order to fetch incidents.

# Authentication

You can use the following methods to authenticate Microsoft Defender for Endpoint:

- Cortex XSOAR app
- Client Credentials Flow
- Authorization Code Flow
- Azure Managed Identities

Choose the desired flow under the "Authentication Flow" parameter.

### Authentication Using Cortex XSOAR app

To use the **Cortex XSOAR application** and allow Cortex XSOAR/XSIAM access to Microsoft Defender For Endpoint an administrator has to approve our app using an admin consent flow by clicking this **[link](https://oproxy.demisto.ninja/ms-defender-atp)**.
After authorizing the Cortex XSOAR app, you will get an ID, Token, and Key which should be inserted in the integration instance settings fields.
If you previously had an API V1 configured based on the credentials obtained from this method, refer to the link above to gain new credentials with the relevant permissions.

For more information, refer to this [documentation](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application).


### Authentication Using Client Credentials Flow

Use the [client credentials flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows:~:text=Client%20Credentials%20Flow%23)
to link Microsoft Defender For Endpoint with Cortex XSOAR/XSIAM.

For this flow you must use a self-deployed application. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
For more details, follow [Self Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application:~:text=Self%20Deployed%20Application%23).

After creating your application with the required permissions (see below),
create an instance of Microsoft Defender XDR in your XSOAR/XSIAM environment.
Then follow the steps under the Client Credentials Flow section [here](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows:~:text=then%20click%20%22Test%22.-,Authorization%20Code%20flow%23,-Some%20Cortex%20XSOAR).

### Authentication Using Authorization Code Flow

Use the [authorization code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows:~:text=then%20click%20%22Test%22.-,Authorization%20Code%20flow%23,-Some%20Cortex%20XSOAR)
to link Microsoft Defender For Endpoint with Cortex XSOAR/XSIAM.

For this flow you must use a self-deployed application. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
For more details, follow [Self Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application:~:text=Self%20Deployed%20Application%23).

After creating your application with the required permissions (see below),
create an instance of Microsoft Graph Secuirty in your XSOAR/XSIAM environment.
Then follow the steps under the Authorization Code Flow section [here](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows:~:text=then%20click%20%22Test%22.-,Authorization%20Code%20flow%23,-Some%20Cortex%20XSOAR).


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
