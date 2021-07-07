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


## Authorization Code Flow

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Copy the following URL and replace the ***TENANT_ID***, ***CLIENT_ID***, and ***REDIRECT_URI*** with your own tenant ID(token), client ID and redirect URI, accordingly.
```https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize?response_type=code&scope=https://api.security.microsoft.com/.default&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI```
3. Enter the link and you will be prompted to grant Cortex XSOAR permissions. You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
4. Copy the ***AUTH_CODE*** (without the “code=” prefix) and paste it in your instance configuration under the **Authorization code** parameter. 
5. Enter your client(application) ID in the ***Application ID*** parameter. 
6. Enter your client secret in the ***Client Secret*** parameter.
7. Enter your tenant ID in the ***Token*** parameter.
8. Enter your redirect URI in the ***Redirect URI*** parameter.
9. Execute the ***!microsoft-365-defender-auth-test*** command.

#### Required Permissions
 * offline_access - Delegate
 * AdvancedHunting.Read - Delegate
 * Incident.ReadWrite - Delegate

----
Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
