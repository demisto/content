Full documentation for this integration is available at our [reference docs](https://xsoar.pan.dev/docs/reference/integrations/azure-sentinel).


## Authorize Cortex XSOAR for Azure Sentinel

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. In your registered app - create new Client secret.
   - navigate in the Azure Portal to ***App registrations > yor registered application > Certificates & secrets*** and click on ***+ New client secret***
   - copy the new secret value and enter it in the ***Client Secret*** parameter.
3. Enter your tenant ID in the ***Tenant ID*** parameter.
4. Enter your registered app Application (client) ID in the ***Client ID*** parameter. 


## Configure the server url
If you have dedicated servel url - enter it in the ***Server URL*** parameter. 

## Get the additional instance parameters

To get the ***Subscription ID***, ***Workspace Name*** and ***Resource Group*** parameters, navigate in the Azure Portal to ***Azure Sentinel > YOUR-WORKSPACE > Settings*** and click on ***Workspace Settings*** tab.

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
