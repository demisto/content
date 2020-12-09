In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to Azure Network Security Group using either XSOAR or self deployed application, after filling out the required parameters, you'll need to run *!azure-nsg-auth-start*, follow the instructions that'll be prompted and then run *!azure-nsg-auth-complete*.

At end of the process you'll see a message that you've managed to log in. 

#### Cortex XSOAR Azure app

In order to use the Cortex XSOAR Azure application, use the default application ID (d4736600-e3d5-4c97-8e65-57abd2b979fe).

You only need to fill out your subscrition ID and resource group name. 

#### Self Deployed Azure app

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have `user_impersonation` permission and must allow public client flows (Can be found under `Authentication` section of the app).
