In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to Azure Web Application Firewall using either the Cortex XSOAR Azure or Self Deployed Azure application:
1. Fill in the required parameters
2. Run the ***!azure-waf-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!azure-waf-auth-complete*** command.
At end of the process, you will see a message that you logged in successfully. 

#### Cortex XSOAR Azure app
In order to use the Cortex XSOAR Azure application, use the default application ID (cf22fd73-29f1-4245-8e16-533704926d20) and fill in your subscription ID and default resource group name. 
#### Self Deployed Azure app
To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
The application must have *user_impersonation* permission and must allow public client flows (which can be found under the **Authentication** section of the app).
