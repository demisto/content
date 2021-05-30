Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard-compliant authentication services, which use an Application to sign-in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are 2 application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

In order to use Cortex XSOAR application and allow us access to Microsoft Graph Mail, an admin has to approve our app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-graph-mail).
After authorizing the Demisto app, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields.

Important to know:
New commands were added to the integration, which require different application permissions:
- ***msgraph-mail-create-draft***
- ***msgraph-mail-send-draft***
- ***msgraph-mail-reply-to***
- ***send-mail***

To use these commands and to fetch incidents,
you will need to add to your application the *Mail.Send application* permission (not delegated),
and re-authorize your integration's instance.

If you do not wish to use these commands, you may keep your integration credentials the same.
