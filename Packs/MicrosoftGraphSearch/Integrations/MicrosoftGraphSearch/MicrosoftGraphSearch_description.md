# Authentication
### Authentication Based on Azure Active Directory Applications

Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard compliant authentication services, which use an application to sign in or delegate authentication. For more information, see the Microsoft identity platform overview.

There is only one application authentication method available:

 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)