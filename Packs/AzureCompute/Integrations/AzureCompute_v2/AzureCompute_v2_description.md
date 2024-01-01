Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard-compliant authentication services, which use an Application to sign-in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are 2 application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application - Client Credentials Flow](https://xsoar-pan-dev--pull-request-1441-nl0wj7at.web.app/docs/reference/articles/microsoft-integrations---authentication#client-credentials-flow)

Depending on the authentication method that you use, the integration parameters might change.

To use the **Cortex XSOAR application** and allow us access to Azure Compute, an administrator has to approve our app using an admin consent flow by clicking this **[link](https://oproxy.demisto.ninja/ms-azure-compute)**.
After authorizing the Cortex XSOAR app, you will get an ID, Token, and Key which should be inserted in the integration instance settings fields.
After giving consent, the application must have a role assigned, so it can access the relevant resources per subscription. 
