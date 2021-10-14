Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

The API this integration uses is defined as beta by Microsoft.

---
To connect to the Azure Active Directory Identity Protection using either the Cortex XSOAR Azure application or the Self-Deployed Azure application, do one of the following:

- **Cortex XSOAR Azure application**: Use application ID `4ffef4a4-601f-4393-a789-432f3f3b8470`, and fill in your subscription ID (from the Azure Portal).
- **Self Deployed Azure application**: Do the following:
   1. Add a new Azure App Registration in the Azure Portal, with the following permissions:
   - `IdentityRiskEvent.Read.All`
   - `User.Read`
   - `IdentityRiskyUser.ReadWrite.All`
  Permission requirements of the different commands are detailed in the integration documentation.
   2. Copy the **Application (client) ID** and **Subscription ID** in the Azure Portal and add it to the instance settings in Cortex XSOAR. 

Once the instance is set up, perform the following steps to log in: 
1. Run the `!azure-ad-auth-start` command.
2. Follow the instructions that appear.
3. Run the `!azure-ad-auth-complete` command.

At the end of the process, a confirmation message appears. 

**Note:** the `Test` button is not functional for instances of this integration, run the `!azure-ad-auth-test` command to test the connection.
