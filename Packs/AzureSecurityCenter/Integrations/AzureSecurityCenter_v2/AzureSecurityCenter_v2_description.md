Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard-compliant authentication services, which use an Application to sign-in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are 2 application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

To allow us access to Azure Security Center, an administrator has to approve the Demisto app using an admin consent flow, by clicking [here](https://oproxy.demisto.ninja/ms-azure-sc).
After authorizing the Demisto app, you will receive an ID, Token, and Key, which needs to be added to the integration instance configuration's corresponding fields. After giving consent, the application must have a role assigned, so it can access the relevant resources per subscription. 
For more information, see the integration documentation.
