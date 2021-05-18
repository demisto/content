To allow access to EWS O365, an administrator has to approve the Demisto app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-ews-o365).
After authorizing the Demisto app, you will get an ID, Token, and Key, which needs to be added to the integration instance configuration's corresponding fields.

### Required Permissions for self deployed Azure Applications
#### Office 365 Exchange Online
**full_access_as_app** - To set this permission follow [the Microsoft documentation](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth#configure-for-app-only-authentication).
You can't manage the **Office 365 Exchange Online** app permissions via the Azure portal.
