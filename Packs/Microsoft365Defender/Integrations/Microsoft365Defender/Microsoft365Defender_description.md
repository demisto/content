## Methods to Authenticate Microsoft Defender XDR
You can use the following methods to authenticate Microsoft Defender XDR.
- Device Code Flow
- Device Code Flow using Cortex XSOAR app
- Client Credentials Flow
- Azure Managed Identities

### Device Code Flow 
___
Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Microsoft Defender XDR with Cortex XSOAR/XSIAM.

In order to use the Cortex XSOAR application, use the default application ID:
```9093c354-630a-47f1-b087-6768eb9427e6```

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
For more details, follow [Self Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application:~:text=Self%20Deployed%20Application%23).

To connect to the Microsoft Defender XDR:
1. Fill in the Client ID parameter of your application under the ID/Client ID parameter.
2. Run the ***!microsoft-365-defender-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!microsoft-365-defender-auth-complete*** command, you are supposed to get a message "authorization completed successfully".
5. You can run the ***!microsoft-365-defender-auth-test** command to test the connection.

At the end of the process you'll see a message that you've logged in successfully.


#### Required Permissions
* microsoft-365-defender-incidents-list:
    * offline_access - Delegated 
    * AdvancedQuery.Read.All - Application - can be found under WindowsDefenderATP on the "APIs my organization uses" section.
      
      And one of the following:
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

Follow these steps:

1. In the instance configuration, select the ***Use Client Credentials Authorization Flow*** checkbox.
2. Enter your Client/Application ID in the ***Application ID*** parameter. 
3. Enter your Client Secret in the ***Client Secret*** parameter.
4. Enter your Tenant ID in the ***Tenant ID*** parameter.
5. Run the ***microsoft-365-defender-auth-test*** command to test the connection and the authorization process.

#### Required Permissions
 * AdvancedHunting.Read.All - Application
 * Incident.ReadWrite.All - Application

### Azure Managed Identities Authentication
____
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).
