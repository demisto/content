# Ansible Azure
Manage Azure services.

To use this integration you must generate a Service Principal for your Azure subscription. Follow [Microsoft's guide](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal) on how to create a Azure AD application and associated service principal.

After stepping through the guide you will have:

* Your Client ID, which is found in the “client id” box in the “Configure” page of your application in the Azure portal
* Your Secret key, generated when you created the application. You cannot show the key after creation. If you lost the key, you must create a new one in the “Configure” page of your application.
* And finally, a tenant ID. It’s a UUID (e.g. ABCDEFGH-1234-ABCD-1234-ABCDEFGHIJKL) pointing to the AD containing your application. You will find it in the URL from within the Azure portal, or in the “view endpoints” of any given URL.