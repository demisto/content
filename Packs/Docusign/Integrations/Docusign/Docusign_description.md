### Customer events
[Customer events API docs](https://developers.docusign.com/docs/monitor-api/reference/monitor/dataset/getstream/)

### User data
[User data API docs](https://developers.docusign.com/docs/admin-api/how-to/audit-users/)

### Request application consent
To use the DocuSign integration and allow access to DocuSign events, an administrator has to approve our app using an admin consent flow by running the ***!docusign-generate-consent-url*** command.

### IMPORTANT:
You only need to get consent from a user for a given set of scopes once. In subsequent authentication workflows, you can skip this step unless you are requesting a different set of scopes or authenticating a different user.
