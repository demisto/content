## Methods to Authenticate Microsoft Defender XDR
You can use the following methods to authenticate Microsoft Defender XDR.
- Device Code Flow
- Client Credentials Flow
- Azure Managed Identities

### Device Code Flow
___

Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Microsoft Defender XDR with Cortex XSOAR.

To connect to the Microsoft Defender XDR:
1. Fill in the required parameters.
2. Run the ***!microsoft-365-defender-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!microsoft-365-defender-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR App

In order to use the Cortex XSOAR application, use the default application ID.
```9093c354-630a-47f1-b087-6768eb9427e6```

#### Self-Deployed Application - Device Code Flow

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. For more details, follow [Self Deployed Application - Device Code Flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow).

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
Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the instance configuration, select the ***Use Client Credentials Authorization Flow*** checkbox.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Client Secret*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.
6. Run the ***microsoft-365-defender-auth-test*** command to test the connection and the authorization process.

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
