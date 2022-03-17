## Application Authorization Flow

* To allow Cortex XSOAR to access Gmail, you need to approve the Demisto App (for GSuite Admins) or create your own app (for all other account types).
* To approve the Demisto app, follow the steps in 'GSuite Admins'.
* To create your own app, follow the steps in 'All Account Types'.
* Once you have the app, follow the steps in 'Authorization Flow In Cortex XSOAR' section to configure OAuth 2.0 authorization in Cortex XSOAR.
* See formal documentation [Authorization Flow In Cortex XSOAR](https://xsoar.pan.dev/docs/reference/integrations/gmail-single-user#Authorization-Flow-In-Cortex-XSOAR).

### GSuite Admins:

**Note**: The Demisto App goes through the Google verification process and is not fully verified. You may receive from Google an "unverified app" warning in the authorization flow.

You can choose to trust the Demisto App so users can configure the app:
1. Go to [App Access Control](https://admin.google.com/ac/owl/list?tab=apps).
2. Choose: `Configure new app` -> `OAuth App Name Or Client ID`. 
3. Enter the following Client ID: `391797357217-pa6jda1554dbmlt3hbji2bivphl0j616.apps.googleusercontent.com`
   You should see the `Demisto App` in the results page. 
4. Select the app and grant the app access as `Trusted`.
5. Add the Demisto app client ID `391797357217-pa6jda1554dbmlt3hbji2bivphl0j616.apps.googleusercontent.com` to the integration configuration.
6. Proceed to 'Authorization Flow In Cortex XSOAR' section to configure OAuth 2.0 authorization in Cortex XSOAR.


### All Account Types:

If you are not a GSuite Admin, you must use your own Google app instead of the default Demisto app.
1. Go to the [developers credentials page](https://console.developers.google.com/apis/credentials) (you may need to set up a [new project](https://cloud.google.com/resource-manager/docs/creating-managing-projects) if you haven't already).
2. If needed, configure the [Consent Screen](https://developers.google.com/workspace/guides/configure-oauth-consent). Fill in the Consent Screen information you want to display to your users.
3. Make sure in the consent screen that you publish the app by clicking `Publish App` and confirming.
4. In the credentials page choose: `Create Credentials` -> `OAuth client ID`.
5. When creating the OAuth client ID, select **iOS** as the type (this type allows apps to work only with a client ID). **iOS** is the type used for all apps which are not Android (including desktop types).
6. Name the app and bundle. You can choose a dummy bundle ID such as `com.demisto.app`.
7. Make sure to [enable the Gmail API](https://console.developers.google.com/apis/api/gmail.googleapis.com/overview) if you haven't already.
8. After you create the app, copy the *client id* of the app that you created to the integration configuration.
9. Proceed to 'Authorization Flow In Cortex XSOAR' section to configure OAuth 2.0 authorization in Cortex XSOAR.

### Authorization Flow In Cortex XSOAR
1. Create and save an integration instance of the Gmail Single User integration. Do not fill in the *Auth Code* field, this is obtained in the next steps.
2. To obtain the **Auth Code**, run the following command in the playground: ***!gmail-auth-link***. Access the link you receive to authenticate your Gmail account.
3. If you get a message from Google saying that it cannot verify the application, click **proceed** and click enter for the app name to give the app you created permissions to your Google account. Then click **proceed**.
4. Complete the authentication process and copy the received code to the **Auth Code** configuration parameter of the integration instance. 
5. Save the instance.
6. To verify that authentication was configured correctly, run the ***!gmail-auth-test***.
