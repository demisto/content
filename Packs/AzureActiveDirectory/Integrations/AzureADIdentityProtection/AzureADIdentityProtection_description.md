Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

The API this integration uses is defined as beta by Microsoft.

---
To connect to the Azure Active Directory Identity Protection, choose between the following Azure app options. Both of them use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

#### Cortex XSOAR Azure app
To use the Cortex XSOAR Azure app, use the default application ID `4ffef4a4-601f-4393-a789-432f3f3b8470` and fill in your subscription ID.

#### Self Deployed Azure app 
To use a self-deployed Azure app, add a new Azure App Registration in the Azure Portal
1. The app must allow public client flows (which can be found under the **Authentication** section of the app).
2. The app must be multi-tenant.
3. The app should be granted the permissions listed in [here](https://xsoar.pan.dev/docs/reference/integrations/azure-active-directory-identity-protection#required-permissions). 
4. Copy the **Application (client) ID** and **Subscription ID** in the Azure Portal and add it to the instance settings in Cortex XSOAR. 
 
---

Once the instance is set up, perform the following steps to log in: 
1. Run the `!azure-ad-auth-start` command.
2. Follow the instructions that appear.
3. Run the `!azure-ad-auth-complete` command.

At the end of the process, a confirmation message appears. 

**Note:** the `Test` button is not functional for instances of this integration, run the `!azure-ad-auth-test` command to test the connection.
