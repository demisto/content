## Device Code Flow

### Microsoft 365 Defender

Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Microsoft 365 Defender with Cortex XSOAR.

To connect to the Microsoft 365 Defender:
1. Fill in the required parameters.
2. Run the ***!microsoft-365-defender-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!microsoft-365-defender-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR App

In order to use the Cortex XSOAR application, use the default application ID.
```9093c354-630a-47f1-b087-6768eb9427e6```

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. For more details, follow [Self Deployed Application - Device Code Flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow).

#### Required Permissions
* microsoft-365-defender-incidents-list:
    * offline_access - Delegated 
      
      And one of the following:
      * Incident.Read.All	- Application
      * AdvancedHunting.Read.All - Application
    

* microsoft-365-defender-incident-update:
   * offline_access - Delegated
   * Incident.ReadWrite.All - Application


* microsoft-365-defender-advanced-hunting:
    * offline_access - Delegated   
    * AdvancedHunting.Read.All - Application


## Client Credentials Flow

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. Select the ***self-deployed*** button.
2. Enter your Client/Application ID in the ***Application ID*** parameter. 
3. Enter your Client Secret in the ***Client Secret*** parameter.
4. Enter your Tenant ID in the ***Tenant ID/Token*** parameter.
5. Run the ***microsoft-365-defender-auth-test*** command to test the connection and the authorization process.

#### Required Permissions
 * AdvancedHunting.Read.All - Application
 * AdvancedHunting.Read.All - Application
 * Incident.ReadWrite.All - Application

----
Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
