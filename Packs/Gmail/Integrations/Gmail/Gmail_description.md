This API enables you to use the Google Admin API. In order to enable the API, you will need to create an account service private key JSON file and copy its content as the value for the **Password** parameter field.

Follow these steps to [create a private key and authorize the API](https://developers.google.com/admin-sdk/directory/v1/guides/delegation).

| Function | API to Authorize |
| -------- | ---------------- |
| Authorize the next APIs for the service account | [https://www.googleapis.com/auth/admin.directory.user.readonly](https://www.googleapis.com/auth/admin.directory.user.readonly) |
| Fetch user roles | [https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly](https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly) |
| Revoke user roles | [https://www.googleapis.com/auth/admin.directory.rolemanagement](https://www.googleapis.com/auth/admin.directory.rolemanagement) |
| Search user mailboxes | [https://www.googleapis.com/auth/gmail.readonly](https://www.googleapis.com/auth/gmail.readonly) |
| Delete emails from user mailbox | [https://mail.google.com](https://mail.google.com), [https://www.googleapis.com/auth/gmail.modify](https://www.googleapis.com/auth/gmail.modify) |
| Fetch user security tokens | [https://www.googleapis.com/auth/admin.directory.user.security](https://www.googleapis.com/auth/admin.directory.user.security) |
| Fetch mobile info | [https://www.googleapis.com/auth/admin.directory.device.mobile.readonly](https://www.googleapis.com/auth/admin.directory.device.mobile.readonly) |
| Perform actions on mobile devices | [https://www.googleapis.com/auth/admin.directory.device.mobile.action](https://www.googleapis.com/auth/admin.directory.device.mobile.action) |
| Perform actions on Chrome devices | [https://www.googleapis.com/auth/admin.directory.device.chromeos](https://www.googleapis.com/auth/admin.directory.device.chromeos) |
| Block email addresses | [https://www.googleapis.com/auth/gmail.settings.basic](https://www.googleapis.com/auth/gmail.settings.basic) |
| Get auto-replay messages from a user | [https://mail.google.com](https://mail.google.com), [https://www.googleapis.com/auth/gmail.modify](https://www.googleapis.com/auth/gmail.modify), [https://www.googleapis.com/auth/gmail.readonly](https://www.googleapis.com/auth/gmail.readonly) and [https://www.googleapis.com/auth/gmail.settings.basic](https://www.googleapis.com/auth/gmail.settings.basic) |
| Set auto-replay messages | [https://www.googleapis.com/auth/gmail.settings.basic](https://www.googleapis.com/auth/gmail.settings.basic) |
| Hide users from the global directory | [https://www.googleapis.com/auth/admin.directory.user](https://www.googleapis.com/auth/admin.directory.user) |
| Delegate a user to a mailbox or remove a delegated mail from a mailbox | [https://www.googleapis.com/auth/gmail.settings.sharing](https://www.googleapis.com/auth/gmail.settings.sharing) |
| Set a user's password | [https://www.googleapis.com/auth/admin.directory.user](https://www.googleapis.com/auth/admin.directory.user) |
| Send mails or reply to a mail | [https://www.googleapis.com/auth/gmail.compose](https://www.googleapis.com/auth/gmail.compose) and [https://www.googleapis.com/auth/gmail.send](https://www.googleapis.com/auth/gmail.send) |
| Add the send as email ID | [https://www.googleapis.com/auth/gmail.settings.sharing](https://www.googleapis.com/auth/gmail.settings.sharing)  |
| Add the forwarding address for the user | [https://www.googleapis.com/auth/gmail.settings.sharing](https://www.googleapis.com/auth/gmail.settings.sharing) |

For the email user parameter, select a user with admin permissions and make sure that you follow the steps to perform Google Apps Domain-Wide Delegation of Authority.

## Revoke/Fetch User Roles
In order to revoke/fetch user role, you will need the Immutable Google Apps ID param.
To get an Immutable Google Apps ID (or customerId):
1. Go to [https://admin.google.com](https://admin.google.com)
2. Select **Security -> Set up single sign-on (SSO)**.

There you will see URLs in the format:
[https://accounts.google.com/o/saml2/idp?idpid=Cxxxxxxxx](https://accounts.google.com/o/saml2/idp?idpid=Cxxxxxxxx)
Cxxxxxxxx is your Immutable Google Apps ID (customerId).
 
