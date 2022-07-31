##### There are two ways to authenticate to the Microsoft 365 Defender:
1. *Device Code Flow*.
2. *Client Credentials Flow*.

### Client Credentials Flow
___

Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard-compliant authentication services, which use an Application to sign-in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are 2 application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

To allow us access to Microsoft Defender Advanced Threat Protection, an admin has to approve our app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-defender-atp).
After authorizing the Demisto app, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields.

### Device Code Flow
___

In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

To connect to the Microsoft Defender for Endpoint using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!microsoft-atp-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!microsoft-atp-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully. 