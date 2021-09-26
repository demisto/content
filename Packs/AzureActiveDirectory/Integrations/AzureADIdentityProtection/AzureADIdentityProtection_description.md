Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

The API this integration uses is defined as beta by Microsoft.

---
To connect to the Azure Active Directory Identity Protection using either the Cortex XSOAR Azure application or the Self-Deployed Azure application:

- **Cortex XSOAR Azure application**: Use application ID `4ffef4a4-601f-4393-a789-432f3f3b8470`, and fill in your subscription ID.
- **Self Deployed Azure application**: Add a new Azure App Registration in the Azure Portal, with the following permissions:
   - `IdentityRiskEvent.Read.All`
   - `User.Read`
   - `IdentityRiskyUser.ReadWrite.All`, used to update user status, for example by calling the `!azure-ad-identity-protection-risky-user-confirm-compromised` command.


Once you have an instance set up, perform the following steps to log in: 
1. Run the `!azure-ad-auth-start` command.
2. Follow the instructions that appear.
3. Run the `!azure-ad-auth-complete` command.

At the end of the process, a confirmation message appears. 

**Note:** the `Test` button is not functional for instances of this integration, run the `!azure-ad-auth-test` command to test the connection.