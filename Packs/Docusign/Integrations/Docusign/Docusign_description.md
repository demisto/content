# Prerequisites

The Docusign app needs to be configured as follows:

| **Data element** | **Description** |
|------------------|-----------------|
| You have defined an [integration key](https://developers.docusign.com/platform/configure-app/#integration-key). | An integration key identifies your integration and links to its configuration values. [Create an integration key.](https://developers.docusign.com/platform/configure-app/#how-to-get-an-integration-key) |
| You have defined a [redirect URI](https://developers.docusign.com/platform/configure-app/#redirect-uri) for your integration key. | The redirect URI is the URL to which Docusign redirects the browser after authentication. [Set a redirect URI.](https://developers.docusign.com/platform/configure-app/#how-to-set-a-redirect-uri) |
| Your application has an [RSA key pair](https://developers.docusign.com/platform/configure-app/#rsa-key-pair). | [Add the RSA key pair.](https://developers.docusign.com/platform/configure-app/#add-the-rsa-key-pair)<br>Note: You can define a maximum of 5 RSA key pairs. If you have already defined 5 key pairs, you must delete one of them before creating a new one. |

### Request application consent
To use the Docusign integration and allow access to Docusign events, an administrator has to approve our app using an admin consent flow by running the ***!docusign-generate-consent-url*** command.

### IMPORTANT:
Consent is only required once per user for a given set of scopes. In subsequent authentication workflows, you can skip this step unless you are requesting a different set of scopes or authenticating a different user.
