Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard-compliant authentication services, which use an Application to sign-in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are 2 application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

To allow access to Microsoft Graph Groups, an administrator has to approve the Demisto app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-graph-groups).
After authorizing the Demisto app, you will get an ID, Token, and Key, which needs to be added to the integration instance configuration's corresponding fields.

