Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

The API this integration uses is defined as beta by Microsoft.

---

To connect to the Azure Active Directory Identity Protection using either the Cortex XSOAR Azure application or the Self-Deployed Azure application:
1. Fill in the required parameters.
2. Make sure to provide the following permissions:   
   - IdentityRiskEvent.Read.All
   - User.Read
   - IdentityRiskyUser.ReadWrite.All - used to update user status, for example by calling the !azure-ad-identity-protection-risky-user-confirm-compromised command.
3. Run the !azure-ad-auth-start command.
4. Follow the instructions that appear.
5. Run the !azure-ad-auth-complete command.

At the end of the process, a confirmation message appears. 
