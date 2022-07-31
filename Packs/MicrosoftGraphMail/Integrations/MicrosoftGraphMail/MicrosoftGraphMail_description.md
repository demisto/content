Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard-compliant authentication services, which use an Application to sign-in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are 2 application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

In order to use Cortex XSOAR application and allow us access to O365 Outlook Mail (Using Graph API), an admin has to approve our app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-graph-mail).
After authorizing the Demisto app, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields.

### Using National Cloud
Using a national cloud endpoint is supported by setting the *Server URL* parameter to one of the following options:
* US Government GCC-High Endpoint: `https://graph.microsoft.us`
* US Government Department of Defence (DoD) Endpoint: `https://dod-graph.microsoft.us`
* Microsoft 365 Germany Endpoint: `https://graph.microsoft.de`
* Microsoft Operated by 21Vianet Endpoint: `https://microsoftgraph.chinacloudapi.cn`

Please refer to [Microsoft Integrations - Using National Cloud](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#using-national-cloud) for more information.


Important to know:
New commands were added to the integration, which require different application permissions:
- ***msgraph-mail-create-draft***
- ***msgraph-mail-send-draft***
- ***msgraph-mail-reply-to***
- ***send-mail***

## Look-Back Parameter Notes
* In case the **look-back** parameter is initialized with a certain value and during a time that incidents/emails were fetched, if changing 
the look back to a number that is greater than the previous value, then in the initial incident fetching there will be incidents duplications.
* If the integration was already set with look back > 0, and the look-back is not being increased at any point of time, then those incident duplications would not occur.


To use these commands and to fetch incidents,
you will need to add to your application the *Mail.Send application* permission (not delegated),
and re-authorize your integration's instance.

If you do not wish to use these commands, you may keep your integration credentials the same.