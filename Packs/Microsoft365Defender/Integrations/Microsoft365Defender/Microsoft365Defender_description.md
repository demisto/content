###Microsoft 365 Defender

Use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) to...

To connect to the Microsoft 365 Defender:
1. Fill in the required parameters.
2. Run the ***!microsoft-365-defender-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!microsoft-365-defender-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR App

In order to use the Cortex XSOAR application, use the default application ID (9093c354-630a-47f1-b087-6768eb9427e6).


#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (9093c354-630a-47f1-b087-6768eb9427e6).

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.

#### Required Permissions
* Incident.ReadWrite.All - Application
* Incident.Read.All	- Application
* AdvancedHunting.Read.All - Application
