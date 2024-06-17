Azure Resource Graph is an Azure service designed to extend Azure Resource Management by providing efficient and performant resource exploration with the ability to query at scale across a given set of resources.

Full documentation for this integration is available in the [reference docs](https://xsoar.pan.dev/docs/reference/integrations/azure-resource-graph).


## Authorize Cortex XSOAR for Azure Resource Graph - Self-Deployed Configuration
To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, go to the [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).

---

In the self-deployed mode, you can authenticate by using Client Credentials flow


### Client Credentials Flow

---
Follow these steps for client-credentials configuration.

1. In the instance configuration under **Advanced Settings**, select the **Use a self-deployed Azure application** checkbox.
2. Enter your Client ID in the **ID / Client ID** parameter. 
3. Enter your Client Secret in the **Key / Client Secret** parameter.
4. Enter your Tenant ID in the **Tenant ID** parameter.
5. Click **Test** to validate the URLs, token, and connection.
