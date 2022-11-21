## Authorization
##### There are two ways to authenticate to the Microsoft Graph Services:
1. *Client Credentials Flow* (Recommended).
2. *Device Code Flow*.


### Client Credentials Flow (Recommended)
___
Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the instance configuration, under the ***Authentication Type*** field select the ***Client Credentials*** option.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Password*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.
6. Run the ***!msgraph-apps-auth-test*** command to test the connection and the authorization process.


### Device Code Flow
___

Use the [device code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
to link Microsoft Graph Services with Cortex XSOAR.

In order to connect to Microsoft Graph Services using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. In the instance configuration, under the ***Authentication Type*** field select the ***Device*** option.
2. Fill in the required parameters.
3. Run the ***!msgraph-apps-auth-start*** command.
4. Follow the instructions that appear.
5. Run the ***!msgraph-apps-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (6b071e63-f701-454b-9e54-ede4c96483e6).

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.

----

#### Required Permissions
* Application.ReadWrite.All - Application
