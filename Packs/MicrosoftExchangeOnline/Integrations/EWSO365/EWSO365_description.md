## Set up the Third Party System

There are two application authentication methods available.
Follow your preferred method's guide on how to use the admin consent flow in order to receive your authentication information:

* [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
* [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application) - Client Credential Flow.

## Set up on Cortex

To allow access to EWS O365, an administrator has to approve the Demisto app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-ews-o365).
After authorizing the Demisto app, you will get an ID, Token, and Key, which needs to be added to the integration instance configuration's corresponding fields.

## Permissions Needed

In order to function as expected, set the following permissions:

**Impersonation rights** to the service account.
**eDiscovery** permissions to the Exchange Server.
**full_access_as_app** to the _application used for authentication_.

Fore more information check the [documentation](https://xsoar.pan.dev/docs/reference/integrations/ewso365)