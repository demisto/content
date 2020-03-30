To allow us access to Azure Sentinel, you need to approve our app, by clicking on the following [link](https://oproxy.demisto.ninja/ms-azure-sentinel).
After authorizing the Demisto app, you will receive an ID, Refresh Token, and Key, which needs to be added to the integration instance configuration's corresponding fields.
 
In addition, you need to fill your subscription ID and resource group, which are found in the Azure portal under Azure Sentinel Workspaces > Settings > {YOUR-WORKSPACE-NAME}.

For a self-deployed configuration, paste the following URL in your browser's address bar:
https://login.microsoftonline.com/common/oauth2/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&resource=https://management.core.windows.net
