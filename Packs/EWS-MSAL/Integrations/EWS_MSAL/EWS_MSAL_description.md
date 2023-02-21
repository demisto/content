The EWS MSAL integration provides the similar functions from EWS O365. This integration is used for clients who wants to authenticate Azure AD Self deployed application using Username and Password (ROPC Flow https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc). This ROPC authentication method allows an application to sign in the user by directly handling their password.

### Required Permissions for self deployed Azure Applications to use with this integration
1. Create a **Self Deployed Application**
![image](https://user-images.githubusercontent.com/41276379/216853216-4dc11717-0e38-4190-97c7-32ba98444406.png)
2. Click **Register** and note the Tenant ID and Application (client) ID to use for the integration parameter
![image](https://user-images.githubusercontent.com/41276379/216853265-6559fea0-7665-4c47-a19d-e864dc389008.png)
3. Go to **Authentication** menu on the left, under **Allow public client flows** select **Enable the following mobile and desktop flows**
![image](https://user-images.githubusercontent.com/41276379/216853315-be737f2a-732b-458a-9bfc-d799c7e6fb2b.png)
4. Go to **API Permission** and grant Microsoft Graph - **EWS.AccessAsUser.All** permission
![image](https://user-images.githubusercontent.com/41276379/216853385-83bed714-4f72-486a-9015-7db1a8ed5d26.png)
5. Grant Admin Consent
![image](https://user-images.githubusercontent.com/41276379/216853440-8a7fd889-bef6-4c6d-a544-2d697a752384.png)