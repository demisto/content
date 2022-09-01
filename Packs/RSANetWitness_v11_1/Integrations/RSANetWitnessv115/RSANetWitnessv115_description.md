Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

# Configure the Integration

## Log in
To log in, use your RSA NetWitness server URL and the supplied username and password.

## Default Service ID
You can use a default service ID for all commands that require this parameter.
To use a different service ID for a specific command, use the *service_id* argument to overwrite the default.

## Permissions
To make requests through the NetWitness Platform API, users must have **integration-server.api.access** permission. This permission is granted automatically to users with the **Admin** or **DPOs - Data Privacy Officer** role.
You can either assign a user one of these roles, or create a new role with the API permission and assign the user the new role.

### Assign a Role to a User
1. Log in as the admin user and go to Admin > Security.
2. In the **Users** tab, select a user and click the edit button.
3. In the **Roles** section:
   1. Click the plus sign.
   2. Select a role and click Add.
4. Click Save.

### Create a New Role
1. Log in as the admin user and go to Admin > Security.
2. Click the **Roles** tab.
3. In the toolbar, click the plus sign to add a new role.
5. In the **Permissions** section click the arrows until you find the **Integration-Server** and choose the **integration-server.api.access** permission.

See [full RSA NetWitness documentation for user management and permissions](https://community.rsa.com/t5/netwitness-platform-online/system-security-and-user-management-guide-11-5/ta-p/572690).
