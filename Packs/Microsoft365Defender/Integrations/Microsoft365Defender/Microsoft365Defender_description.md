
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

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.

#### Required Permissions
* microsoft-365-defender-incidents-list (one of the following):
    * Incident.Read.All	- Application
    * AdvancedHunting.Read.All - Application
    

* microsoft-365-defender-incident-update:
   * Incident.ReadWrite.All - Application


* microsoft-365-defender-advanced-hunting:
    * AdvancedHunting.Read.All - Application
  
Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.