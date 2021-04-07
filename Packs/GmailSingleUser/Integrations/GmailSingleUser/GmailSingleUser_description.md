## Application Authorization Flow

To allow Demisto to access Gmail, the user has to approve the Demisto app using an OAuth 2.0 authorization flow. Follow these steps to authorize the Demisto app in Gmail.

1. Create and save an integration instance of the Gmail Single User integration. Do not fill in the *Auth Code* field, this will be obtained in the next steps.
2. To obtain the **Auth Code** run the following command in the playground: ***!gmail-auth-link***. Access the link you receive to authenticate your Gmail account. 
3. Complete the authentication process and copy the received code to the **Auth Code** configuration parameter of the integration instance. 
4. Save the instance.
5. To verify that authentication was configured correctly, run the ***!gmail-auth-test***.

## Application Configuration Options
See the [Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/gmail-single-user) for additional App configuration options:
* **GSuite Admins:** How to trust the Demisto App.
* **Bring your own App:** Use your own App instead of the default Demisto App. 

----
Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

