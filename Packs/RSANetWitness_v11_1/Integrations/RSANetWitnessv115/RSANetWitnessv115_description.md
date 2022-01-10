# How to configure the integration
Use your RSA Netwitness server url, and the supplied username and password used for login.

## Default Service ID
You can enter a defaults Serivce ID to be used in all commands that require this parameter.
To use a different Service ID in a single command use the service_id argument to run over the default

## Permissions
In order to make requests through the NetWitness Platform API, users must have the **integration-server.api.access** permission. This permission is granted automatically to users with **Admin** role or **DPOs - Data Privacy Officer** role.
You can either give the desired user one of these roles, or create a new role and give it the API permissions.

**How to assign a role to a user-**
1. Login as admin user and goto Admin > Security.
2. In the Users tab, select a user and click the edit button.
3. In the Roles section- 
   1. click the plus sign
   2. select a role and click Add.
4. Click Save.

**How to create a new role-**
1. Login as admin user and goto Admin > Security.
2. Click the Roles tab.
3. In the Roles tab, click the plus sign in the toolbar to add a new role.
5. In the Permissions section cilk the arrows until you find the **Integration-Server** and choose the **integration-server.api.access** permission.

see full RSA NetWitness documentation for user management and permissions [here](https://community.rsa.com/t5/netwitness-platform-online/system-security-and-user-management-guide-11-5/ta-p/572690).
Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.