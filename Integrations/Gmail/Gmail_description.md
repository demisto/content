This API enables the usage of Google Admin API. In order to enable it, you will need to create an account service private key json file and copy its content.
Follow the steps here to create such a private key and authorize the API for usage: [https://developers.google.com/admin-sdk/directory/v1/guides/delegation](https://developers.google.com/admin-sdk/directory/v1/guides/delegation)

It is necessary to authorize the next API's for that service account:
[https://www.googleapis.com/auth/admin.directory.user.readonly](https://www.googleapis.com/auth/admin.directory.user.readonly)

In order to fetch user roles, please authorize this api too: [https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly](https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly)

In order to revoke user roles, please authorize this api too: [https://www.googleapis.com/auth/admin.directory.rolemanagement](https://www.googleapis.com/auth/admin.directory.rolemanagement)

In order to search user mailboxes, please authorize this api too: [https://www.googleapis.com/auth/gmail.readonly](https://www.googleapis.com/auth/gmail.readonly)

In order to delete emails from user mailbox, please authorize this api too: 
[https://mail.google.com](https://mail.google.com), 
[https://www.googleapis.com/auth/gmail.modify](https://www.googleapis.com/auth/gmail.modify)

In order to fetch user security tokens, please authorize this api too: [https://www.googleapis.com/auth/admin.directory.user.security](https://www.googleapis.com/auth/admin.directory.user.security)

In order to fetch mobile info, please authorize this api too: [https://www.googleapis.com/auth/admin.directory.device.mobile.readonly](https://www.googleapis.com/auth/admin.directory.device.mobile.readonly)

In order to preform actions on mobile devices, please authorize this api too: [https://www.googleapis.com/auth/admin.directory.device.mobile.action](https://www.googleapis.com/auth/admin.directory.device.mobile.action)

In order to preform actions on chorme devices, please authorize this api too:[https://www.googleapis.com/auth/admin.directory.device.chromeos](https://www.googleapis.com/auth/admin.directory.device.chromeos)

In order to block email addresses, please authorize this api too:
[https://www.googleapis.com/auth/gmail.settings.basic](https://www.googleapis.com/auth/gmail.settings.basic)

For the email user param, please choose a user with admin permissions and make sure that you follow the steps to perform Google Apps Domain-Wide Delegation of Authority.

In order to revoke/fetch user role, you will need the Immutable Google Apps ID param.
To get an Immutable Google Apps ID (or customerId):
1. Go to [https://admin.google.com](https://admin.google.com)
2. Security -> Set up single sign-on (SSO)

You will see there URLs in the format:
[https://accounts.google.com/o/saml2/idp?idpid=Cxxxxxxxx](https://accounts.google.com/o/saml2/idp?idpid=Cxxxxxxxx)
Cxxxxxxxx is your Immutable Google Apps ID (customerId).

In order to get auto-replay messages from a user, please authorize this api too: 
https://mail.google.com,
https://www.googleapis.com/auth/gmail.modify,
https://www.googleapis.com/auth/gmail.readonly
and https://www.googleapis.com/auth/gmail.settings.basic

In order to set auto-replay messages, please authorize this api too: https://www.googleapis.com/auth/gmail.settings.basic

In order to hide users from the global directory, please authorize this api too: https://www.googleapis.com/auth/admin.directory.user

In order to delegate a user to a mailbox or remove a delegated mail from a mailbox, please authorize this api too: https://www.googleapis.com/auth/gmail.settings.sharing

In order to set a user's password, please authorize this api too: https://www.googleapis.com/auth/admin.directory.user

In order to send mails, please authorize this api too:
https://www.googleapis.com/auth/gmail.compose and https://www.googleapis.com/auth/gmail.send
 
