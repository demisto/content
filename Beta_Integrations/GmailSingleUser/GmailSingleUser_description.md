To allow access to Gmail, the user has to approve the Demisto app using an oauth2 authorization flow. Perform the following steps:
* Create an integration instance and save it. Do not fill in the *Auth Code* configuration yet, this will be obtained in the next steps.
* Run the following command in the playground: *!gmail-auth-link*. Follow the received link to authenticate your Gmail account. After Completing the authentication process, copy the received code to the **Auth Code** configuration parameter of the integration instance. Save the instance.
* Run the following command to verify that authentication has been setup correctly: *!gmail-auth-test*.

**Note:** The Demisto App is being verified through the Google verification process. During this time period, while the app is not fully verified, you may receive from Google an "unverified app" warning in the authorization flow.

**Optional:** You may choose to use your own Google App instead of the default Demisto App. Create your own App by following [Google's instruction for Desktop Apps](https://developers.google.com/identity/protocols/OAuth2InstalledApp#prerequisites). When creating the OAuth client ID, choose **iOS** as the type (this is the type used for Desktop Apps). Once created, copy the *client id* to the integration configuration. Then go through the oauth2 authorization flow detailed above.

---
Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
