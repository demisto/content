## Methods to Authenticate Microsoft Defender XDR
You can use the following methods to authenticate Microsoft Defender XDR.
- Device Code Flow
- Cortex XSOAR App (Using Device Code Flow)
- Client Credentials Flow
- Azure Managed Identities

Choose the desired flow under the "Authentication Flow" parameter.

### Device Code Flow 
___
Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Microsoft Defender XDR with Cortex XSOAR/XSIAM.

In order to use the Cortex XSOAR application, use the default application ID:
```9093c354-630a-47f1-b087-6768eb9427e6```

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
For more details, follow [Self Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application:~:text=Self%20Deployed%20Application%23).

After creating your application with the required permissions (see below),
create an instance of Microsoft Defender XDR in your XSOAR/XSIAM environment.
Then follow the steps under the Device Code Flow section [here](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows:~:text=XSOAR/XSIAM%20CLI.-,Device%20Code%20Flow%23,-Some%20Cortex%20XSOAR).


#### Required Permissions
* microsoft-365-defender-incidents-list:
    * offline_access - Delegated 
    * AdvancedQuery.Read.All - Application - can be found under WindowsDefenderATP on the "APIs my organization uses" section.
    * And one of the following:
      * Incident.Read.All	- Application - See section 4 in [this article](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-user-context?view=o365-worldwide#create-an-app)
      * AdvancedHunting.Read.All - Application - See section 4 in [this article](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-user-context?view=o365-worldwide#create-an-app)



* microsoft-365-defender-incident-update:
   * offline_access - Delegated
   * AdvancedQuery.Read.All - Application - can be found under WindowsDefenderATP on the "APIs my organization uses" section.
   * Incident.ReadWrite.All - Application - See section 4 in [this article](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-user-context?view=o365-worldwide#create-an-app)



* microsoft-365-defender-advanced-hunting:
    * offline_access - Delegated   
    * AdvancedHunting.Read.All - Application - See section 4 in [this article](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-user-context?view=o365-worldwide#create-an-app)

    
### Client Credentials Flow
___
Use the [client credentials flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows:~:text=Client%20Credentials%20Flow%23)
to link Microsoft Defender XDR with Cortex XSOAR/XSIAM.

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
For more details, follow [Self Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application:~:text=Self%20Deployed%20Application%23).

After creating your application with the required permissions (see below),
create an instance of Microsoft Defender XDR in your XSOAR/XSIAM environment.
Then follow the steps under the Client Credentials Flow section [here](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authentication-flows:~:text=then%20click%20%22Test%22.-,Authorization%20Code%20flow%23,-Some%20Cortex%20XSOAR).


#### Required Permissions
 * AdvancedHunting.Read.All - Application
 * Incident.ReadWrite.All - Application

### Azure Managed Identities Authentication
____
#### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- #### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- #### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).
